# -------------------------------------------------------------------------
#                     The CodeChecker Infrastructure
#   This file is distributed under the University of Illinois Open Source
#   License. See LICENSE.TXT for details.
# -------------------------------------------------------------------------
"""
Prepare and start different analisys types
"""
import copy
import json
import os
import shlex
import subprocess
import sys
import time
from datetime import datetime

from libcodechecker import client
from libcodechecker.logger import LoggerFactory
from libcodechecker.analyze import analysis_manager
from libcodechecker.analyze import analyzer_env
from libcodechecker.analyze import skiplist_handler
from libcodechecker.analyze.analyzers import analyzer_types

LOG = LoggerFactory.get_new_logger('ANALYZER')


def prepare_actions(actions, enabled_analyzers):
    """
    Set the analyzer type for each buildaction.
    Multiple actions if multiple source analyzers are set.
    """
    res = []

    for ea in enabled_analyzers:
        for action in actions:
            new_action = copy.deepcopy(action)
            new_action.analyzer_type = ea
            res.append(new_action)
    return res


def __print_analyzer_version(context, analyzer_config_map):
    """
    Print the path and the version of the analyzer binary.
    """
    check_env = analyzer_env.get_check_env(context.path_env_extra,
                                           context.ld_lib_path_extra)

    # Get the analyzer binaries from the config_map which
    # contains only the checked and available analyzers.
    for analyzer_name, analyzer_cfg in analyzer_config_map.items():
        LOG.info("Using analyzer:")
        analyzer_bin = analyzer_cfg.analyzer_binary
        print(analyzer_bin)
        version = [analyzer_bin, u' --version']
        try:
            subprocess.call(shlex.split(' '.join(version)), env=check_env)
        except OSError as oerr:
            LOG.warning("Failed to get analyzer version: " + ' '.join(version))
            LOG.warning(oerr.strerror)


def _get_skip_handler(args):
    try:
        if args.skipfile:
            LOG.debug_analyzer("Creating skiplist handler.")
            return skiplist_handler.SkipListHandler(args.skipfile)
    except AttributeError:
        LOG.debug_analyzer('Skip file was not set in the command line')


def run_check(args, actions, context):
    """
    Prepare:
    - analyzer config handlers
    - skiplist handling
    - analyzer severity levels

    Stores analysis related data to the database and starts the analysis.
    """

    if args.jobs <= 0:
        args.jobs = 1

    LOG.debug_analyzer("Checking supported analyzers.")
    enabled_analyzers = analyzer_types.check_supported_analyzers(
        args.analyzers,
        context)

    actions = prepare_actions(actions, enabled_analyzers)

    suppress_file = ''
    try:
        suppress_file = os.path.realpath(args.suppress)
    except AttributeError:
        LOG.debug_analyzer('Suppress file was not set in the command line.')

    # Create one skip list handler shared between the analysis manager workers.
    skip_handler = _get_skip_handler(args)

    issue_tags = {"suppress": "issue",
                  "high" : "issue",
                  "medium" : "issue",
                  "low" : "issue",
                  "style" : "issue"} 

    with client.get_connection() as connection:
        context.run_id = connection.add_checker_run(' '.join(sys.argv),
                                                    args.name,
                                                    context.version,
                                                    str(datetime.now()))
        for tag_name, tag_type in issue_tags.iteritems():
            connection.store_tag(tag_name, tag_type)

        # Clean previous suppress information.
        # FIXME when should we clean suppress data?
        #client.clean_suppress(connection, report_id)

        if os.path.exists(suppress_file):
            client.send_suppress(context.run_id, connection, suppress_file)

        analyzer_config_map = analyzer_types. \
            build_config_handlers(args,
                                  context,
                                  enabled_analyzers,
                                  connection)

        if skip_handler:
            connection.add_skip_paths(context.run_id,
                                      skip_handler.get_skiplist())

    __print_analyzer_version(context, analyzer_config_map)

    LOG.info("Static analysis is starting ...")
    start_time = time.time()

    analysis_manager.start_workers(args,
                                   actions,
                                   context,
                                   analyzer_config_map,
                                   skip_handler)

    end_time = time.time()

    with client.get_connection() as connection:
        connection.finish_checker_run(context.run_id, str(datetime.now()))

    LOG.info("Analysis length: " + str(end_time - start_time) + " sec.")


def run_quick_check(args,
                    context,
                    actions):
    """
    This function implements the "quickcheck" feature.
    No result is stored to a database.
    """

    enabled_analyzers = analyzer_types. \
        check_supported_analyzers(args.analyzers, context)

    actions = prepare_actions(actions, enabled_analyzers)

    analyzer_config_map = \
        analyzer_types.build_config_handlers(args,
                                             context,
                                             enabled_analyzers)

    __print_analyzer_version(context, analyzer_config_map)

    LOG.info("Static analysis is starting ...")

    analysis_manager.start_workers(args, actions, context, analyzer_config_map,
                                   _get_skip_handler(args), False)
