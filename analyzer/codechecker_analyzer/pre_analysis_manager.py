# -------------------------------------------------------------------------
#                     The CodeChecker Infrastructure
#   This file is distributed under the University of Illinois Open Source
#   License. See LICENSE.TXT for details.
# -------------------------------------------------------------------------
"""
Run pre analysis, collect statistics or CTU data.
"""


import multiprocessing
import os
import shutil
import signal
import sys
import traceback
import uuid

from codechecker_analyzer import env
from codechecker_common.logger import get_logger

from .analyzers import analyzer_base
from .analyzers.clangsa import ctu_manager, ctu_triple_arch
from .analyzers.clangsa import statistics_collector
from .analyzers.clangsa.analyzer import ClangSA


LOG = get_logger('analyzer')


def collect_statistics(action, source, config, environ, statistics_data):
    """
    Run the statistics collection command and save the
    stdout and stderr to a file.
    """
    cmd, can_collect = statistics_collector.build_stat_coll_cmd(action,
                                                                config,
                                                                source)

    if not can_collect:
        LOG.debug('Can not collect statistical data.')
        return

    LOG.debug_analyzer(cmd)

    ret_code, analyzer_out, analyzer_err = \
        analyzer_base.SourceAnalyzer.run_proc(cmd, env=environ)

    LOG.debug(analyzer_out)
    LOG.debug(analyzer_err)
    if ret_code:
        LOG.error("Failed to collect statistics for %s", source)
        return ret_code

    LOG.debug("Running statistics collectors for %s was sucesssful.",
              source)

    _, source_filename = os.path.split(source)

    output_id = source_filename + str(uuid.uuid4()) + '.stat'

    stat_for_source = os.path.join(statistics_data['stat_tmp_dir'],
                                   output_id)

    with open(stat_for_source, 'w', encoding="utf-8", errors="ignore") as out:
        out.write(analyzer_out)
        out.write(analyzer_err)

    return ret_code



def pre_analyze(params):

    action, context, analyzer_config_map, skip_handler, \
        ctu_data, statistics_data, processed_var, actions_num = params

    analyzer_environment = env.extend(context.path_env_extra,
                                      context.ld_lib_path_extra)

    with processed_var.get_lock():
        processed_var.value += 1

    if skip_handler and skip_handler.should_skip(action.source):
        return
    if action.analyzer_type != ClangSA.ANALYZER_NAME:
        return

    _, source_filename = os.path.split(action.source)

    LOG.info("[%d/%d] %s",
             processed_var.value,
             actions_num.value, source_filename)

    config = analyzer_config_map.get(ClangSA.ANALYZER_NAME)

    try:
        if ctu_data:
            LOG.debug("running CTU pre analysis")
            ctu_temp_fnmap_folder = ctu_data.get('ctu_temp_fnmap_folder')
            ctu_func_map_cmd = ctu_data.get('ctu_func_map_cmd')

            triple_arch = \
                ctu_triple_arch.get_triple_arch(action, action.source,
                                                config,
                                                analyzer_environment)
            ctu_manager.generate_ast(triple_arch, action, action.source,
                                     config, analyzer_environment)
            ctu_manager.map_functions(triple_arch, action, action.source,
                                      config, analyzer_environment,
                                      ctu_func_map_cmd,
                                      ctu_temp_fnmap_folder)

    except Exception as ex:
        LOG.debug_analyzer(str(ex))
        traceback.print_exc(file=sys.stdout)
        raise

    try:
        if statistics_data:
            LOG.debug("running statistics pre analysis")
            collect_statistics(action,
                               action.source,
                               config,
                               analyzer_environment,
                               statistics_data)

    except Exception as ex:
        LOG.debug_analyzer(str(ex))
        traceback.print_exc(file=sys.stdout)
        raise


def run_pre_analysis(actions, context, analyzer_config_map,
                     jobs, skip_handler, ctu_data, statistics_data, manager):
    """
    Run multiple pre analysis jobs before the actual analysis.
    """
    LOG.info('Pre-analysis started.')
    if ctu_data:
        LOG.info("Collecting data for ctu analysis.")
    if statistics_data:
        LOG.info("Collecting data for statistical analysis.")

    def signal_handler(signum, frame):
        try:
            pool.terminate()
            manager.shutdown()
        finally:
            sys.exit(128 + signum)

    signal.signal(signal.SIGINT, signal_handler)

    processed_var = multiprocessing.Value('i', 0)
    actions_num = multiprocessing.Value('i', len(actions))

    pool = multiprocessing.Pool(jobs)

    if statistics_data:
        # Statistics collection is enabled setup temporary
        # directories.
        stat_tmp_dir = os.path.join(statistics_data.get('stats_out_dir'),
                                    'tmp')

        # Cleaning previous outputs.
        if os.path.exists(stat_tmp_dir):
            shutil.rmtree(stat_tmp_dir)

        os.makedirs(stat_tmp_dir)

        statistics_data['stat_tmp_dir'] = stat_tmp_dir

    try:
        collect_actions = [(build_action,
                            context,
                            analyzer_config_map,
                            skip_handler,
                            ctu_data,
                            statistics_data,
                            processed_var,
                            actions_num)
                           for build_action in actions]

        pool.map_async(pre_analyze, collect_actions)
        pool.close()
    except Exception:
        pool.terminate()
        raise
    finally:
        pool.join()

    # Postprocessing the pre analysis results.
    if ctu_data:
        ctu_manager.merge_ctu_func_maps(
                ctu_data.get('ctu_dir'),
                ctu_data.get('ctu_func_map_file'),
                ctu_data.get('ctu_temp_fnmap_folder'))

    if statistics_data:

        stats_in = statistics_data.get('stat_tmp_dir')
        stats_out = statistics_data.get('stats_out_dir')

        statistics_collector.postprocess_stats(stats_in, stats_out,
                                               statistics_data.get(
                                                   'stats_min_sample_count'),
                                               statistics_data.get(
                                                   'stats_relevance_threshold')
                                               )

        if os.path.exists(stats_in):
            LOG.debug('Cleaning up temporary statistics directory')
            shutil.rmtree(stats_in)
    LOG.info('Pre-analysis finished.')
