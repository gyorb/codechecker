# -------------------------------------------------------------------------
#                     The CodeChecker Infrastructure
#   This file is distributed under the University of Illinois Open Source
#   License. See LICENSE.TXT for details.
# -------------------------------------------------------------------------
"""
ORM model.
"""
from __future__ import unicode_literals

from datetime import datetime

from sqlalchemy import *
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import *
from sqlalchemy.sql.expression import true

CC_META = MetaData(naming_convention={
    "ix": 'ix_%(column_0_label)s',
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(column_0_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
})

# Create base class for ORM classes.
Base = declarative_base(metadata=CC_META)


# Start of ORM classes.

class DBVersion(Base):
    """
    Store schema version information used to check compatibility.
    With alembic automatic schema migration done but that is not
    available for SQLite now.
    """

    __tablename__ = 'db_versions'
    # TODO: constraint, only one line in this table
    major = Column(Integer, primary_key=True)
    minor = Column(Integer, primary_key=True)

    def __init__(self, major, minor):
        self.major = major
        self.minor = minor


class File(Base):
    """
    Main identification of a file is based on the content hash.
    """

    __tablename__ = 'files'

    fhash = Column(String, primary_key=True)
    filepath = Column(String)

    def __init__(self, fhash, filepath):
        self.fhash = fhash
        self.filepath = filepath


class FileMeta(Base):
    """
    Store additional information for the source files.

    Entry should be deleted if file is deleted.
    """

    __tablename__ = 'file_metas'

    fhash = Column(String, ForeignKey('files.fhash',
                                      deferrable=True,
                                      initially="DEFERRED",
                                      ondelete='CASCADE'),
                                      primary_key=True)
    # bzipped file content
    content = Column(Binary)

    def __init__(self, fhash, content):
        self.fhash = fhash
        self.content = content


class Run(Base):
    """
    One analysis run related data.
    """

    __tablename__ = 'runs'

    run_id = Column(Integer, autoincrement=True, primary_key=True)
    name = Column(String)
    version = Column(String) # CodeChecker version used for this run.
    start_date = Column(String) # FIXME convert to DateTime thrift api string to datetime conversion needed
    end_date = Column(String) # FIXME convert to DateTime thrift api string to datetime conversion needed

    def __init__(self, run_name):
        self.name = run_name

    def start(self, date):
        self.start_date = date

    def finish(self, date):
        self.end_date = date

    def set_version(self, version):
        self.version = version


class RunMeta(Base):
    """
    Additional informations for each run which might be interesting.

    Entry should be deleted if run is deleted.
    """

    __tablename__ = 'run_metas'

    run_id = Column(Integer,
                    ForeignKey('runs.run_id',
                               deferrable=True,
                               initially="DEFERRED",
                               ondelete='CASCADE'),
                               primary_key=True)
    # Bzip compressed run command.
    run_cmd = Column(Binary)

    def __init__(self, run_id):
        self.run_id = run_id

    def set_run_cmd(self, run_cmd):
        self.run_cmd = run_cmd


class RunToTag(Base):
    """
    Assign tags to runs.

    Entry should be deleted if run is deleted.
    """

    __tablename__ = 'run_to_tags'

    id = Column(Integer, autoincrement=True, primary_key=True)
    run_id = Column(String,
                    ForeignKey('runs.run_id',
                               deferrable=True,
                               initially="DEFERRED",
                               ondelete='CASCADE'))
    tagid = Column(Integer,
                   ForeignKey('tags.id',),
                   nullable=False)

    def __init__(self, run_name, tagid):
        self.run_name = run_name
        self.tagid = tagid


class RunToReport(Base):
    """
    Assign reports to runs.

    Entry should be deleted if run is deleted.
    """

    __tablename__ = 'run_to_reports'

    id = Column(Integer, autoincrement=True, primary_key=True)
    run_id = Column(Integer, ForeignKey('runs.run_id',
                                        deferrable=True,
                                        initially="DEFERRED",
                                        ondelete='CASCADE'))

    report_id = Column(String, ForeignKey('reports.report_id'))

    def __init__(self, run_id, report_id):
        self.run_id = run_id
        self.report_id = report_id


class CompilationAction(Base):
    """
    Compilation actions.

    Entry should be deleted if run is deleted.
    """

    __tablename__ = 'compilation_actions'

    # Hash of the compilation action.
    chash = Column(String, primary_key=True)

    run_id = Column(Integer, ForeignKey('runs.run_id',
                                        deferrable=True,
                                        initially="DEFERRED",
                                        ondelete='CASCADE'))

    compilation_cmd = Column(Binary) # Bzipped compilation commmand.

    def __init__(self, chash, run_id, compilation_cmd):
        self.chash = chash
        self.run_id = run_id
        self.compilation_cmd = compilation_cmd


class AnalysisAction(Base):
    """
    Store the constructed analysis action and the
    analyzer related data (type) if available.
    """

    __tablename__ = 'analysis_actions'

    # Hash of the analysis action.
    ahash = Column(String, primary_key=True)

    run_id = Column(Integer, ForeignKey('runs.run_id',
                                        deferrable=True,
                                        initially="DEFERRED",
                                        ondelete='CASCADE'))
    analyzer_type = Column(String)

    def __init__(self, ahash, analyzer_type, run_id):
        self.ahash = ahash
        self.run_id = run_id
        self.analyzer_type = analyzer_type


class AnalysisActionMeta(Base):
    """
    Additional analysis action related informations
    which might be interesting or can help debugging.

    Should be deleted if AnalysisAction is deleted.
    """

    __tablename__ = 'analysis_action_metas'

    ahash = Column(String, ForeignKey('analysis_actions.ahash',
                                      deferrable=True,
                                      initially="DEFERRED",
                                      ondelete='CASCADE'),
                                      primary_key=True)

    analysis_cmd = Column(Binary) # bzipped analysis cmd
    msg = Column(Binary) # failure or other msg, bziped

    def __init__(self, ahash, analysis_cmd):
        self.ahash = ahash
        self.analysis_cmd = analysis_cmd

    def set_msg(self, msg):
        self.msg = msg


class DiagSection(Base):
    """
    Diagnostic sections store report related informations.
    One report contains multiple diagnoscic sections which
    can build a path or just various events/messages/notes ...

    Line and column positions highly depend on the source content!
    """

    __tablename__ = 'diag_sections'

    id = Column(Integer, autoincrement=True, primary_key=True)

    # to which file it belongs to
    fhash = Column(String, ForeignKey('files.fhash',
                                      deferrable=True,
                                      initially="DEFERRED",
                                      ondelete='CASCADE'))

    report_id = Column(String, ForeignKey('reports.report_id'))

    line_begin = Column(Integer)
    line_end = Column(Integer)
    col_begin = Column(Integer)
    col_end = Column(Integer)
    msg = Column(Binary)
    kind = Column(Integer)
    position = Column(Integer) # set only if part of diagnostic path

    def __init__(self, file_hash, report_id,
                 line_begin, line_end,
                 col_begin, col_end,
                 msg, kind, position):

        self.fhash = file_hash
        self.report_id = report_id
        self.line_begin = line_begin
        self.line_end = line_end
        self.col_begin = col_begin
        self.col_end = col_end
        self.msg = msg
        self.kind = kind
        self.position = position


class Report(Base):
    """
    Report related information.
    """

    __tablename__ = 'reports'

    # Should be a unique id which identifies only one report!
    report_id = Column(String, primary_key=True)

    # Report hash.
    bhash = Column(String)

    # Hash of the diagnostic path.
    phash = Column(String)

    # Main report message provided by an analyzer.
    msg = Column(String)

    # Analyzer checker name.
    checker_name = Column(String)

    # Checker category if available.
    category = Column(String)

    # Report type if available.
    report_type = Column(String)

    def __init__(self, report_id, bhash, phash,
                 checker_name, category,
                 report_type, msg):

        self.report_id = report_id
        self.bhash = bhash
        self.phash = phash
        self.checker_name = checker_name
        self.category = category
        self.report_type = report_type
        self.msg = msg


class ReportToTag(Base):
    """
    Assign a tag to a report.
    """

    __tablename__ = 'report_to_tags'

    id = Column(Integer, autoincrement=True, primary_key=True)
    report_id = Column(String,
                       ForeignKey('reports.report_id',
                                  deferrable=True,
                                  initially="DEFERRED",
                                  ondelete='CASCADE'))

    tagid = Column(Integer, ForeignKey('tags.id'), nullable=False) 

    def __init__(self, report_id, tagid):
        self.report_id = report_id
        self.tagid = tagid


class ReportComment(Base):
    """
    Additional comments can be added to each report
    by automated tools or bby the users.
    """

    __tablename__ = 'report_comments'

    id = Column(Integer, autoincrement=True, primary_key=True)
    report_id = Column(String,
                       ForeignKey('reports.report_id',
                                  deferrable=True,
                                  initially="DEFERRED",
                                  ondelete='CASCADE'))

    # Comments like: label added, first detected or comment by user
    comment = Column(String)
    date = Column(DateTime)
    comment_by = Column(String)

    def __init__(self, report_id, comment, comment_by):
        self.report_id = report_id
        self.comment = comment
        self.comment_by = comment_by
        self.date = datetime.now()


class Suppress(Base):
    """
    Suppression information for the reports.
    """

    __tablename__ = 'suppresses'

    id = Column(Integer, autoincrement=True, primary_key=True)
    report_id = Column(String,
                       ForeignKey('reports.report_id',
                                  deferrable=True,
                                  initially="DEFERRED",
                                  ondelete='CASCADE'))
    comment = Column(String)

    def __init__(self, report_id, filename, comment):
        self.report_id = report_id
        self.comment = comment

    def set_comment(self, comment):
        self.comment = comment


class Tag(Base):
    """
    Special tags like severity or suppress should be filled up
    automatically.

    Severity levels are handled as tags: 'high', 'low', 'style' ...

    Suppress as tag: 'suppressed'

    Additional custom tags by the user.

    Tag kind: issue, run, none ...
     * issue: can be applied only to issues
     * run: can be applied only to runs (nightly, CI results ...)
     * vrun: virtual run special tag to group runs together

    """

    __tablename__ = 'tags'

    id = Column(Integer, autoincrement=True, primary_key=True)
    name = Column(String)

    kind = Column(String)

    def __init__(self, name, kind):
        self.name = name
        self.kind = kind

# End of ORM classes.


def CreateSchema(engine):
    """
    Creates the schema if it does not exists.
    Do not check version or do migration yet.
    """
    Base.metadata.create_all(engine)


def CreateSession(engine):
    """
    Creates a scoped session factory that can act like a session.
    The factory uses a thread_local registry, so every thread have
    its own session.
    """
    SessionFactory = scoped_session(sessionmaker(bind=engine))
    return SessionFactory
