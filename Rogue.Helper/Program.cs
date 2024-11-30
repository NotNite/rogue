using System.Text;
using Lumina;
using Rogue.Helper;

var lumina = new GameData(args[0], new LuminaOptions {
    PanicOnSheetChecksumMismatch = false
});

switch (args[1]) {
    case "extract": {
        var path = args[2];
        var file = lumina.GetFile(path);
        if (file == null) {
            Environment.Exit(1);
            return;
        }

        var data = file.Data;
        Console.Write(Convert.ToHexString(data));
        break;
    }

    case "sheet": {
        var sheet = args[2];
        uint? row = args.Length > 3 ? uint.Parse(args[3]) : null;
        var serializer = new SheetSerializer(lumina);
        Console.WriteLine(row == null ? serializer.SerializeSheet(sheet) : serializer.SerializeRow(sheet, row.Value));
        break;
    }
}
