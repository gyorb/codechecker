# -------------------------------------------------------------------------
#                     The CodeChecker Infrastructure
#   This file is distributed under the University of Illinois Open Source
#   License. See LICENSE.TXT for details.
# -------------------------------------------------------------------------

import hashlib

class Report(object):

    """
    The report with all information including multiple diagnostic sections.

    There should be at least a main diagnostic section in each report.
    """

    def __init__(self, checker_name, category=None, type=None):

        self.checker_name = checker_name
        self.category = category
        self.type = type
        self.hash_value = None
        self.__path_hash = None

        # main diag section
        self.main_section = None
        # list of diag sections without a path
        self.__diag_sections = []
        # list of diag_sections which belong to a path
        self.__bug_path = None

    def diag_sections(self):
        return self.__diag_sections

    @property
    def file_path(self):
        # FIXME HACK HACK
        # FIXME cleanup filepath from main section should be used everywhere
        # FIXME DELETE THIS
        self.main_section.start_pos.file_path

    @property
    def main_section(self):
        return self.__main_section

    @main_section.setter
    def main_section(self, main_section):
        self.__main_section = main_section

    def add_diag_section(self, section):
        #TODO filter out duplicates
        self.__diag_sections.append(section)

    def get_last_event(self):
        # FIXME the main event should be used like this
        return self.__main_section

    def set_path(self, bug_path):
        self.__bug_path = bug_path

    def get_path(self):
        return self.__bug_path

    @property
    def path_hash(self):
        if not self.__path_hash:
            self.__path_hash = self.__bug_path.path_hash
        return self.__path_hash

    @property
    def report_id(self):
        # FIXME temporary report id generation
        return self.hash_value + "||" + self.path_hash

    @property
    def report_hash(self):
        # FIXME doc!!!!
        return self.hash_value


class GenericEquality(object):

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self.__dict__ == other.__dict__)

    def __ne__(self, other):
        return not self.__eq__(other)


class Position(GenericEquality):
    """
    Represent a postion in a source file.
    """

    def __init__(self, line, col, filepath):
        self.line = line
        self.col = col
        self.file_path = filepath

    def __str__(self):
        msg = "@"+str(self.line)+":"+str(self.col)+"::"+str(self.file_path)
        return msg


class BugPath(object):
    """
    Bug path which contains multiple DiagSections.
    The order of the diagnostic sections in the bug path matters,
    needed to store in the database and for the UI to render arrows properly.
    """
    def __init__(self):
        self.__diag_sections = []
        self.__path_length = 0

    def add_diag(self, diag_section):
        """
        The order of the diagnostic sections in the bug path matters,
        needed for the UI to render arrows properly.
        """
        diag_section.path_position = self.__path_length
        self.__diag_sections.append(diag_section)
        self.__path_length += 1

    def get_diag_sections(self):
        return self.__diag_sections

    def len(self):
        """
        Contains all the control and event diag sections!
        """
        return self.__path_length

    @property
    def path_hash(self):
        """
        Generate a unique id for a bug path.
        """
        # TODO review hash generation
        # FIXME generate bug path hash
        # based on columm numbers in bug path points and event
        # messages and event column numbers
        path = ""
        for ds in self.__diag_sections:
            print(ds)
            path += str(ds.start_pos.col)+ \
                    str(ds.end_pos.col) + \
                    ds.msg + ds.start_pos.file_path

        return hashlib.sha1(path).hexdigest()


class DiagSection(GenericEquality):
    """
    Diagnostic section can have a start and an end position.

    If position_in_path is set this section belongs to a bug path.

    kind sets the kind of this range: event, control, note ...
    """

    def __init__(self,
                 start_pos,
                 end_pos,
                 kind='',
                 msg=''):

        self.start_pos = start_pos

        if not end_pos:
            end_pos = start_pos

        self.end_pos = end_pos

        self.msg = msg

        self.kind = kind

        # position in the path a simple integer
        # not set if DiagSection is not part of a path
        self.position_in_path = None

    @property
    def path_position(self):
        return self.position_in_path

    @path_position.setter
    def path_position(self, position):
        self.position_in_path = position

    def __str__(self):
        msg = "<"+str(self.kind)+"> ["+str(self.position_in_path)+"] \nstart: " + str(self.start_pos) + "\nend: " + str(self.end_pos) + \
        " \n" + self.msg + "\n"
        return msg
