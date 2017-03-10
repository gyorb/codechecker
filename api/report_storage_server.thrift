// -------------------------------------------------------------------------
//                     The CodeChecker Infrastructure
//   This file is distributed under the University of Illinois Open Source
//   License. See LICENSE.TXT for details.
// -------------------------------------------------------------------------

include "shared.thrift"

namespace py DBThriftAPI

struct NeedFileResult {
                1: bool needed;
                2: i64 fileId;
}


// The order of the functions inditaces the order that must be maintained when
// calling into the server.
service CheckerReport {
                // store checker run related data to the database
                // by default updates the run information if name was already found
                i64  addCheckerRun(
                                   1: string command,
                                   2: string name,
                                   3: string version,
                                   4: string start_date)
                                   throws (1: shared.RequestFailed requestError),

                bool replaceConfigInfo(
                                   1: i64 run_id,
                                   2: shared.CheckerConfigList values)
                                   throws (1: shared.RequestFailed requestError),

                # FIXME move to shared service
                bool suppressReport(1: shared.SuppressReportList reportToSuppress)
                                    throws (1: shared.RequestFailed requestError),

                # FIXME move to shared service
                bool unsuppressReport(
                                    1: string report_id,
                                    )
                                    throws (1: shared.RequestFailed requestError),

                # the map contains a path and a comment (can be empty)
                bool addSkipPath(
                                 1: i64 run_id,
                                 2: map<string, string> paths)
                                 throws (1: shared.RequestFailed requestError),

                bool storeTag(1: string name,
                              2: string kind)
                              throws (1: shared.RequestFailed requestError),

                bool deleteTag(1: string name)
                               throws (1: shared.RequestFailed requestError),
 
                # FIXME this should be the tag id not tag name
                # clients should check for valid tags
                bool addTagToIssue(1: string tag_name,
                                   2: string report_id)
                                   throws (1: shared.RequestFailed requestError),

                bool removeTagFromIssue(1: i64 tag_id,
                                        2: string ihash)
                            throws (1: shared.RequestFailed requestError),

                bool addToRun(1: i64 run_id,
                              2: string bug_hash)
                              throws (1: shared.RequestFailed requestError),

                // The next few following functions must be called via the same connection.
                // =============================================================
                string storeAnalysisAction(
                                    1: i64 run_id,
                                    2: string analysis_cmd,
                                    3: string analyzer_type,
                                    4: string analyzed_source_file,
                                    5: string msg)
                                    throws (1: shared.RequestFailed requestError),

                bool storeCompilationAction(
                                    1: i64 run_id,
                                    2: string compilation_cmd_id,
                                    3: string compilation_cmd)
                                    throws (1: shared.RequestFailed requestError),

                bool addReport(
                               1: shared.Report report)
                               throws (1: shared.RequestFailed requestError),


                bool storeReportComment(
                                        1: string report_id,
                                        2: string comment,
                                        3: string comment_by)
                                        throws (1: shared.RequestFailed requestError),

                bool needFileContent(1: string source_file_hash)
                                               throws (1: shared.RequestFailed requestError),

                bool addFileContent(
                                    1: string file_content_hash,
                                    2: string filepath,
                                    3: binary file_content)
                                    throws (1: shared.RequestFailed requestError),

                bool finishCheckerRun(1: i64 run_id,
                                      2: string finish_date)
                                      throws (1: shared.RequestFailed requestError),

                bool stopServer()
                                throws (1: shared.RequestFailed requestError)
}
