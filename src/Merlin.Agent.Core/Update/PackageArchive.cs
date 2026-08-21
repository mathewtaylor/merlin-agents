using System.Formats.Tar;
using System.IO.Compression;

namespace Merlin.Agent.Core.Update;

/// <summary>
/// Extracts ONE named binary out of a downloaded package archive.
/// </summary>
/// <remarks>
/// <para>
/// <b>One archive per (version, RID), carrying both binaries and the query packs.</b> There is one
/// artefact, one address and one hash per version, so the agent and the updater can never be on
/// versions that were never tested together.
/// </para>
/// <para>
/// <b>The swapper takes only the component it is replacing.</b> Unpacking the whole archive over
/// the install directory would overwrite the OTHER binary — the running one, or the one this
/// process is forbidden to touch — which is the single point of failure mutual replacement exists
/// to remove. It would also rewrite <c>queries/</c> underneath a collection that may be in flight.
/// A consequence worth stating plainly: <b>the query packs are NOT refreshed by an update</b>, so a
/// version that adds a query does not start reading it until the machine is reinstalled. A missing
/// query reads as "not observed", which is a visible degradation rather than a wrong answer.
/// </para>
/// <para>
/// <b>Entry names are matched on the FILE NAME, never on the whole path.</b> CI writes the Windows
/// zip with flat entries and the Unix tar with a <c>./</c> prefix, and the two have been different
/// since the first release. Matching the full string would work on one platform and quietly find
/// nothing on the other three.
/// </para>
/// </remarks>
public static class PackageArchive
{
    /// <summary>
    /// The largest a single extracted entry may be.
    /// </summary>
    /// <remarks>
    /// Matched to the swapper's download cap deliberately: a package that arrived inside 256 MB has
    /// no honest reason to expand past it, and the two numbers moving together is easier to keep
    /// true than a second scale nobody remembers the reason for.
    /// </remarks>
    private const long MaximumEntryBytes = 256L * 1024 * 1024;

    /// <summary>The largest number of entries an archive may carry.</summary>
    private const int MaximumEntries = 512;

    /// <summary>
    /// Extracts one component from an archive.
    /// </summary>
    /// <param name="archivePath">The downloaded archive.</param>
    /// <param name="fileName">The file name to extract, e.g. <c>merlin-updater</c>.</param>
    /// <param name="destinationPath">Where to write it.</param>
    /// <returns><c>true</c> when the archive carried that file.</returns>
    public static bool TryExtract(string archivePath, string fileName, string destinationPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(archivePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);
        ArgumentException.ThrowIfNullOrWhiteSpace(destinationPath);

        return IsZip(archivePath)
            ? TryExtractFromZip(archivePath, fileName, destinationPath)
            : TryExtractFromTarGz(archivePath, fileName, destinationPath);
    }

    /// <summary>
    /// Whether an archive is a zip, read from its own first bytes.
    /// </summary>
    /// <remarks>
    /// <b>Sniffed, not inferred from the file extension or the platform.</b> The address is
    /// configured by an operator and the extension can be anything; a Windows machine handed a
    /// <c>.tar.gz</c> should still unpack it rather than fail with a corrupt-zip error nobody can
    /// act on.
    /// </remarks>
    /// <param name="archivePath">The archive.</param>
    /// <returns><c>true</c> when the file begins with the zip local-file-header signature.</returns>
    private static bool IsZip(string archivePath)
    {
        using FileStream stream = File.OpenRead(archivePath);

        Span<byte> header = stackalloc byte[2];

        return stream.ReadAtLeast(header, 2, throwOnEndOfStream: false) == 2
            && header[0] == 0x50
            && header[1] == 0x4B;
    }

    private static bool TryExtractFromZip(string archivePath, string fileName, string destinationPath)
    {
        using ZipArchive archive = ZipFile.OpenRead(archivePath);

        int seen = 0;

        foreach (ZipArchiveEntry entry in archive.Entries)
        {
            Count(ref seen);

            if (!Matches(entry.FullName, fileName))
            {
                continue;
            }

            using Stream content = entry.Open();

            Extract(content, destinationPath);
            return true;
        }

        return false;
    }

    private static bool TryExtractFromTarGz(string archivePath, string fileName, string destinationPath)
    {
        using FileStream file = File.OpenRead(archivePath);
        using GZipStream decompressed = new(file, CompressionMode.Decompress);
        using TarReader reader = new(decompressed);

        int seen = 0;

        while (reader.GetNextEntry() is { } entry)
        {
            Count(ref seen);

            if (entry.EntryType is not (TarEntryType.RegularFile or TarEntryType.V7RegularFile)
                || !Matches(entry.Name, fileName))
            {
                continue;
            }

            // A NULL DataStream MEANS AN EMPTY ENTRY, NOT A MISSING ONE. TarReader only attaches
            // a stream when the entry has a data section, so a zero-byte binary arrives as null —
            // and skipping it would carry on searching and report "the package carries no
            // merlin-agent", which is false and sends whoever reads it after the wrong fault. The
            // extraction this replaced wrote the empty file, the probe then refused to execute it,
            // and the swap failed saying exactly that. Keep the accurate verdict.
            if (entry.DataStream is { } content)
            {
                Extract(content, destinationPath);
            }
            else
            {
                File.WriteAllBytes(destinationPath, []);
            }

            return true;
        }

        return false;
    }

    /// <summary>
    /// Counts an entry against <see cref="MaximumEntries"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>An archive is a handful of files, and a directory of millions is not a package.</b> The
    /// download cap bounds the COMPRESSED bytes, and a central directory of empty entries costs
    /// almost nothing to compress while costing real time to walk. The real package carries two
    /// binaries, three query manifests and a directory entry.
    /// </para>
    /// <para>
    /// <b>It bounds the walk for TAR and only the matching for ZIP.</b> <c>TarReader</c> is
    /// genuinely streaming, so refusing at the 513th entry means the 513th is the last one read.
    /// <c>ZipArchive.Entries</c> parses the entire central directory into memory before the loop
    /// begins, so by the time this refuses, the cost it is refusing has already been paid. Worth
    /// knowing rather than working around: the download cap already bounds those bytes, and the
    /// value here is that the refusal is uniform and the tar path — the one used on both Unix
    /// targets — is genuinely bounded.
    /// </para>
    /// </remarks>
    private static void Count(ref int seen)
    {
        if (++seen > MaximumEntries)
        {
            throw new InvalidDataException(
                $"The package holds more than {MaximumEntries} entries, which no agent package "
                + "does. Nothing was installed.");
        }
    }

    /// <summary>
    /// Writes one entry out, refusing to keep going past <see cref="MaximumEntryBytes"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The 256 MB download cap bounds the COMPRESSED archive and says nothing about what it
    /// expands to.</b> A compressed stream is free to declare very little and produce a great deal,
    /// so an archive that passed every check upstream could still fill the disk — and it would do
    /// it as SYSTEM or root, inside the install tree, on a machine whose whole job is to keep
    /// reporting. Counting the bytes as they are written is the only bound that holds, because the
    /// entry's declared length is a number the archive supplies about itself.
    /// </para>
    /// <para>
    /// <b>It throws rather than returning false</b>, because <c>InvalidDataException</c> is already
    /// what a corrupt archive raises here and the caller's swap already turns it into a reported
    /// <c>Failed</c> outcome. A new return value would need every caller to learn a new case for a
    /// state that is simply "this package is not usable".
    /// </para>
    /// <para>
    /// It stands BEHIND the SHA-256 pin and the compile-time host allowlist, both of which an
    /// attacker must defeat first. That is what makes it defence in depth rather than the control.
    /// </para>
    /// <para>
    /// <b>It does NOT carry the archive's Unix mode across, where <c>ExtractToFile</c> did.</b>
    /// Every caller today follows the extraction with <c>MakeExecutable</c> — before the probe and
    /// again after the commit move — so the executable bit is restored on every path and nothing
    /// depends on the archive's own mode. A future caller that skipped that step would get a file
    /// it cannot run, which is why this is stated rather than left to be discovered.
    /// </para>
    /// </remarks>
    private static void Extract(Stream content, string destinationPath)
    {
        using FileStream target = File.Create(destinationPath);

        byte[] buffer = new byte[81920];
        long total = 0;
        int read;

        while ((read = content.Read(buffer)) > 0)
        {
            total += read;

            if (total > MaximumEntryBytes)
            {
                throw new InvalidDataException(
                    $"A package entry expanded past {MaximumEntryBytes} bytes, which no agent "
                    + "binary approaches. Nothing was installed.");
            }

            target.Write(buffer.AsSpan(0, read));
        }
    }

    private static bool Matches(string entryName, string fileName) =>
        string.Equals(
            Path.GetFileName(entryName.Replace('\\', '/')),
            fileName,
            StringComparison.OrdinalIgnoreCase);
}
