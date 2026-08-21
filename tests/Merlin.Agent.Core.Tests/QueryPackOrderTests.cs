using System.Text.Json;
using Xunit;

namespace Merlin.Agent.Core.Tests;

/// <summary>
/// The query packs are ordered security-posture first and inventory last.
/// </summary>
/// <remarks>
/// <para>
/// <b>The rule was enforced by nothing, which is how the pack that documents it drifted from it.</b>
/// <c>docs/collection-manifest.md</c> states that when the collection budget is reached whatever has
/// not run is reported as NOT OBSERVED, "so what a slow machine gives up is its hostname and chassis
/// type rather than its disk encryption or its firewall" — and each pack's own <c>$comment</c>
/// repeats it. Yet <c>linux.json</c> shipped with <c>kernel</c> LAST, behind two inventory queries,
/// in the same commit that wrote the rule down. A prose rule about the order of entries in a data
/// file is exactly the kind that drifts silently, because nothing compiles against it.
/// </para>
/// <para>
/// <b>The packs are read from the repository, not from a copy.</b> They are linked into this test
/// project's output so the assertion is about the files that ship, and adding a query to a pack
/// without classifying it here fails rather than passing by omission.
/// </para>
/// </remarks>
public sealed class QueryPackOrderTests
{
    /// <summary>
    /// The queries that assert nothing about this machine's security posture, and may therefore be
    /// the ones a spent budget discards.
    /// </summary>
    /// <remarks>
    /// Named rather than inferred: "is this query inventory?" is a judgement about what the reading
    /// is FOR, and writing it down here is what makes a reordering a deliberate act.
    /// </remarks>
    private static readonly Dictionary<string, string[]> _inventory = new(StringComparer.Ordinal)
    {
        ["linux.json"] = ["system_volume", "system_info"],
        ["macos.json"] = ["system_volume", "system_info"],
        ["windows.json"] =
            ["system_drive", "system_info", "machine_guid", "chassis", "entra_join"],
    };

    /// <summary>
    /// How many queries each pack holds, so ADDING one forces a classification rather than
    /// defaulting to posture.
    /// </summary>
    /// <remarks>
    /// <b>Without this the file's own claim was false.</b> An unclassified query is treated as
    /// posture, so a new INVENTORY query inserted anywhere before the existing inventory block
    /// passes silently — it is only caught when it lands at or after the first classified inventory
    /// key. A count is the cheapest thing that cannot be satisfied by omission.
    /// </remarks>
    /// <remarks>
    /// <b>It forces an ACKNOWLEDGEMENT, not a classification</b> — bumping the number and walking
    /// away satisfies it. That is still worth having, because the number cannot be bumped without
    /// reading the rule directly above it, but do not mistake it for the stronger guarantee.
    /// </remarks>
    private static readonly Dictionary<string, int> _expectedCount = new(StringComparer.Ordinal)
    {
        ["linux.json"] = 7,
        ["macos.json"] = 10,
        ["windows.json"] = 16,
    };

    [Theory]
    [InlineData("linux.json")]
    [InlineData("macos.json")]
    [InlineData("windows.json")]
    public void NoInventoryQueryRunsBeforeAPostureQuery(string pack)
    {
        List<string> keys = Keys(pack);
        string[] inventory = _inventory[pack];

        // Every name classified above must actually be in the pack, or the classification has
        // rotted and the assertion below is weaker than it reads.
        foreach (string name in inventory)
        {
            Assert.Contains(name, keys);
        }

        Assert.True(
            _expectedCount[pack] == keys.Count,
            $"{pack} holds {keys.Count} queries, not {_expectedCount[pack]}. Classify the new one "
            + "in _inventory if it is inventory, leave it out if it is posture, and update the "
            + "count either way. Order: " + string.Join(", ", keys));

        // DefaultIfEmpty rather than a bare Max/Min: an all-inventory or all-posture pack would
        // otherwise throw "sequence contains no elements" instead of the message written below.
        int lastPosture = keys
            .Select((name, index) => (name, index))
            .Where(entry => !inventory.Contains(entry.name, StringComparer.Ordinal))
            .Select(entry => entry.index)
            .DefaultIfEmpty(-1)
            .Max();

        int firstInventory = keys
            .Select((name, index) => (name, index))
            .Where(entry => inventory.Contains(entry.name, StringComparer.Ordinal))
            .Select(entry => entry.index)
            .DefaultIfEmpty(keys.Count)
            .Min();

        Assert.True(
            lastPosture < firstInventory,
            $"{pack}: '{keys[firstInventory]}' is inventory and runs before the posture query "
            + $"'{keys[lastPosture]}'. A machine that runs out of budget would give up the posture "
            + "reading and keep the inventory one, which is backwards. Order: "
            + string.Join(", ", keys));
    }

    /// <summary>
    /// The Linux kernel build is that platform's ONLY patch-currency signal, so it is not inventory.
    /// </summary>
    /// <remarks>
    /// <c>LinuxNormaliser</c> reports <c>Patching</c> as null and maps <c>kernel.version</c> into the
    /// OS build, so a machine pending a reboot after a kernel update is visible through this query
    /// and nothing else. It sat last on Linux — behind both inventory queries — which is the drift
    /// this file exists to catch.
    /// </remarks>
    [Fact]
    public void TheLinuxKernelQueryRunsBeforeInventory()
    {
        List<string> keys = Keys("linux.json");

        Assert.True(
            keys.IndexOf("kernel") < keys.IndexOf("system_volume"),
            "kernel must run before system_volume — it is patch currency, not inventory.");
        Assert.True(
            keys.IndexOf("kernel") < keys.IndexOf("system_info"),
            "kernel must run before system_info — it is patch currency, not inventory.");
    }

    /// <remarks>
    /// <para>
    /// <b><c>JsonDocument</c> enumerates properties in DOCUMENT order</b>, which is what lets this
    /// file read an order out of a JSON object at all — it is a read-only view over the original
    /// payload. That is a property of the implementation rather than a documented guarantee of
    /// <c>EnumerateObject</c>, so <c>TheJsonReaderPreservesDocumentOrder</c> pins it: were it ever
    /// to sort or rehash, every assertion here would silently become vacuous.
    /// </para>
    /// <para>
    /// <b>THIS IS NOT THE READER THE AGENT USES, and the difference is not academic.</b>
    /// <c>QueryPack.Load</c> deserialises into a <c>Dictionary&lt;string, QueryPackEntry&gt;</c> and
    /// builds the run order by enumerating it — the exact construct whose own remarks in that file
    /// call its ordering guarantee insufficient. It lives in <c>Merlin.Agent</c>, which this test
    /// project does not reference, so what is asserted here is the order of the FILE and not the
    /// order the agent runs. Closing that needs <c>QueryPack</c> moved into
    /// <c>Merlin.Agent.Core</c> so the shipping loader can be asserted directly; until then this
    /// catches an editing mistake in the pack but not a change of loader. <c>Load</c> also SKIPS an
    /// entry whose <c>sql</c> is blank, which the count below cannot see.
    /// </para>
    /// </remarks>
    [Fact]
    public void TheJsonReaderPreservesDocumentOrder()
    {
        using JsonDocument document =
            JsonDocument.Parse("""{"zulu":1,"alpha":2,"mike":3,"bravo":4}""");

        Assert.Equal(
            ["zulu", "alpha", "mike", "bravo"],
            document.RootElement.EnumerateObject().Select(p => p.Name));
    }

    private static List<string> Keys(string pack)
    {
        string path = Path.Combine(AppContext.BaseDirectory, "queries", pack);

        Assert.True(File.Exists(path), $"The pack {pack} was not copied to the test output.");

        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(path));

        return
        [
            .. document.RootElement.GetProperty("queries").EnumerateObject().Select(p => p.Name),
        ];
    }
}
