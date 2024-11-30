using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using Lumina;
using Lumina.Excel;
using Lumina.Text;

namespace Rogue.Helper;

public class SheetSerializer {
    private readonly Dictionary<string, Type> sheets;
    private readonly GameData gameData;
    private readonly JsonSerializerOptions options;

    public SheetSerializer(GameData gameData) {
        this.gameData = gameData;
        var luminaTypes = Assembly.GetAssembly(typeof(Lumina.Excel.Sheets.Addon))!.GetTypes().ToList();
        this.sheets = luminaTypes
            .Where(t => t.GetCustomAttributes(typeof(SheetAttribute), false).Length > 0
                        && t.Namespace == "Lumina.Excel.Sheets")
            .ToDictionary(t => ((SheetAttribute) t.GetCustomAttributes(typeof(SheetAttribute), false)[0]).Name!);
        this.options = new JsonSerializerOptions {
            Converters = {new SeStringConverter(), new RowRefConverterFactory()},
            ReferenceHandler = ReferenceHandler.IgnoreCycles
        };
    }

    public string? SerializeSheet(string id) {
        var sheet = this.GetTypedSheet(id);
        if (sheet == null) return null;
        return JsonSerializer.Serialize(sheet, this.options);
    }

    public string? SerializeRow(string id, uint rowId) {
        var sheet = this.GetTypedSheet(id);
        if (sheet == null) return null;

        var getRowMethod = sheet.GetType().GetMethod("GetRow", [typeof(uint)]);
        if (getRowMethod == null) return null;

        var row = getRowMethod.Invoke(sheet, [rowId]);
        if (row == null) return null;

        return JsonSerializer.Serialize(row, this.options);
    }

    private object? GetTypedSheet(string id) {
        var type = this.sheets.GetValueOrDefault(id);
        if (type == null) return null;
        var getSheetMethod = typeof(GameData).GetMethod("GetExcelSheet")?.MakeGenericMethod(type);
        return getSheetMethod?.Invoke(this.gameData, [null, null]);
    }
}

public class SeStringConverter : JsonConverter<SeString> {
    public override SeString? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) {
        throw new NotImplementedException();
    }

    public override void Write(Utf8JsonWriter writer, SeString value, JsonSerializerOptions options) {
        try {
            writer.WriteStringValue(value.ToString());
        } catch {
            writer.WriteStringValue(string.Empty);
        }
    }
}

public class RowRefConverterFactory : JsonConverterFactory {
    public override bool CanConvert(Type typeToConvert) {
        return typeToConvert.IsGenericType && typeToConvert.GetGenericTypeDefinition() == typeof(RowRef<>) ||
               typeToConvert == typeof(RowRef);
    }

    public override JsonConverter CreateConverter(Type typeToConvert, JsonSerializerOptions options) {
        if (typeToConvert.IsGenericType && typeToConvert.GetGenericTypeDefinition() == typeof(RowRef<>)) {
            var elementType = typeToConvert.GetGenericArguments()[0];
            var instance = typeof(TypedRowRefConverter<>).MakeGenericType(elementType);
            return (JsonConverter) Activator.CreateInstance(instance)!;
        } else {
            return new RowRefConverter();
        }
    }
}

public class RowRefConverter : JsonConverter<RowRef> {
    public override RowRef Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) {
        throw new NotImplementedException();
    }

    public override void Write(Utf8JsonWriter writer, RowRef value, JsonSerializerOptions options) {
        writer.WriteStartObject();
        writer.WriteNumber("Row", value.RowId);
        writer.WriteEndObject();
    }
}

public class TypedRowRefConverter<T> : JsonConverter<RowRef<T>> where T : struct, IExcelRow<T> {
    public override RowRef<T> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) {
        throw new NotImplementedException();
    }

    public override void Write(Utf8JsonWriter writer, RowRef<T> value, JsonSerializerOptions options) {
        writer.WriteStartObject();
        writer.WriteString("Sheet", typeof(T).Name);
        writer.WriteNumber("Row", value.RowId);
        writer.WriteEndObject();
    }
}
