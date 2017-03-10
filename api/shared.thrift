// -------------------------------------------------------------------------
//                     The CodeChecker Infrastructure
//   This file is distributed under the University of Illinois Open Source
//   License. See LICENSE.TXT for details.
// -------------------------------------------------------------------------

//-----------------------------------------------------------------------------
# FIXME Deprecated. Use DiagnosticSection instead.
struct BugPathEvent {
  1: i64    startLine,
  2: i64    startCol,
  3: i64    endLine,
  4: i64    endCol,
  5: string msg,
  6: string fileId
  7: string filePath
}
typedef list<BugPathEvent> BugPathEvents

//-----------------------------------------------------------------------------
# FIXME Deprecated. Use DiagnosticSection instead.
struct BugPathPos {
  1: i64    startLine,
  2: i64    startCol,
  3: i64    endLine,
  4: i64    endCol,
  5: string fileId
  6: string filePath
}
typedef list<BugPathPos> BugPath

enum DiagSectionKind{
  CONTROL   = 0,
  EVENT     = 1,
  MAIN      = 2
}

struct DiagnosticSection{
  1: i64    startLine,
  2: i64    startCol,
  3: i64    endLine,
  4: i64    endCol,
  5: DiagSectionKind kind,
  6: string msg,
  7: i64    path_position,
  8: string file_id
}

typedef list<DiagnosticSection> Diagnostic

struct Report {
   1: string file_id,
   2: string report_id,
   3: string phash,
   4: string report_hash,
   5: DiagnosticSection main_diag_section,
   6: Diagnostic diagnostic,
   7: string checker_name,
   8: string checker_cat,
   9: string report_type,
}

struct SuppressReportData {
    1: string report_id,
    2: string file_name,
    3: string comment,
    4: bool force_update
}
typedef list<SuppressReportData> SuppressReportList

//-----------------------------------------------------------------------------
struct ConfigValue {
  1: string checker_name,
  2: string attribute,
  3: string value
}
typedef list<ConfigValue> CheckerConfigList

//-----------------------------------------------------------------------------
enum Severity{
  UNSPECIFIED   = 0,
  STYLE         = 10,
  LOW           = 20,
  MEDIUM        = 30,
  HIGH          = 40,
  CRITICAL      = 50
}

//-----------------------------------------------------------------------------
enum ErrorCode{
  DATABASE,
  IOERROR,
  GENERAL,
  PRIVILEGE
}

//-----------------------------------------------------------------------------
exception RequestFailed {
  1: ErrorCode error_code,
  2: string    message
}

