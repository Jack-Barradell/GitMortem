from enum import StrEnum


class ExportFormat(StrEnum):
    TXT = "txt"
    JSON = "json"
    CSV = "csv"
    XLSX = "xlsx"

    @property
    def media_type(self) -> str:
        return _MEDIA_TYPES[self]

    @property
    def extension(self) -> str:
        return self.value


_MEDIA_TYPES = {
    ExportFormat.TXT: "text/plain; charset=utf-8",
    ExportFormat.JSON: "application/json",
    ExportFormat.CSV: "text/csv; charset=utf-8",
    ExportFormat.XLSX: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}
