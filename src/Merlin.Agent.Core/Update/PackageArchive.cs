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

        foreach (ZipArchiveEntry entry in archive.Entries)
        {
            if (!Matches(entry.FullName, fileName))
            {
                continue;
            }

            entry.ExtractToFile(destinationPath, overwrite: true);
            return true;
        }

        return false;
    }

    private static bool TryExtractFromTarGz(string archivePath, string fileName, string destinationPath)
    {
        using FileStream file = File.OpenRead(archivePath);
        using GZipStream decompressed = new(file, CompressionMode.Decompress);
        using TarReader reader = new(decompressed);

        while (reader.GetNextEntry() is { } entry)
        {
            if (entry.EntryType is not (TarEntryType.RegularFile or TarEntryType.V7RegularFile)
                || !Matches(entry.Name, fileName))
            {
                continue;
            }

            entry.ExtractToFile(destinationPath, overwrite: true);
            return true;
        }

        return false;
    }

    private static bool Matches(string entryName, string fileName) =>
        string.Equals(
            Path.GetFileName(entryName.Replace('\\', '/')),
            fileName,
            StringComparison.OrdinalIgnoreCase);
}
