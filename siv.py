#!/usr/bin/env python3

import argparse
import csv
import datetime
import grp
import hashlib
import os
import pwd
import sys

# SUPPORTED_HASHING_FUNCTIONS = list(hashlib.algorithms_available)
SUPPORTED_HASHING_FUNCTIONS = list(hashlib.algorithms_guaranteed)


def eprint(*args, **kwargs):
    """Print to stderr"""
    print(*args, file=sys.stderr, **kwargs)


def is_subpath(base, subpath):
    """Check of base contains subpath"""
    abs_base = os.path.realpath(base)
    abs_subpath = os.path.realpath(subpath)

    # Append separator at the end
    abs_base += '' if abs_base.endswith(os.path.sep) else os.path.sep

    return abs_subpath.startswith(abs_base)


def prompt_yes_no(text):
    answer = input(text + " [Y/n]: ")
    while 1:
        if answer == '' or answer.lower() == 'y':
            return True
        elif answer.lower() == 'n':
            return False

        answer = input("[Y/n]: ")


def get_file_hash(file, hash_object, block_size=65536):
    """Get the hash of the file contents. Returns 'None' on I/O error"""
    try:
        with open(file, 'rb') as f:
            buffer = f.read(block_size)
            while len(buffer) > 0:
                hash_object.update(buffer)
                buffer = f.read(block_size)
    except IOError:
        return None

    return hash_object.hexdigest()


class WalkStats:
    total_directories = 0
    total_files = 0


class FileInfo:
    def __init__(self, path=None, size=None, user=None, group=None, mode=None,
                 modified=None, checksum=None):
        self.path = path
        self.size = None if not size else int(size)
        self.user = user
        self.group = group
        self.mode = mode
        self.modified = modified
        self.checksum = checksum or None

    def __bool__(self):
        return bool(self.path)


def walk_directory_sorted(path, hash_object, walk_stats_object):
    """Recursively walk through a directory"""
    file_info = FileInfo()

    abs_path = os.path.abspath(path)
    for root, dirs, files in sorted(os.walk(abs_path)):
        walk_stats_object.total_directories += 1
        walk_stats_object.total_files += len(files)

        for d in sorted(dirs):
            file_info.path = os.path.join(root, d)
            file_stat = os.stat(file_info.path)

            file_info.size = file_stat.st_size
            file_info.user = pwd.getpwuid(file_stat.st_uid).pw_name
            file_info.group = grp.getgrgid(file_stat.st_gid).gr_name
            file_info.mode = oct(file_stat.st_mode)  # & 0777
            file_info.modified = datetime.datetime \
                .fromtimestamp(file_stat.st_mtime) \
                .strftime('%Y-%m-%d %H:%M:%S')
            file_info.checksum = None

            yield file_info

        for file in sorted(files):
            file_info.path = os.path.join(root, file)
            file_stat = os.stat(file_info.path)

            file_info.size = file_stat.st_size
            file_info.user = pwd.getpwuid(file_stat.st_uid).pw_name
            file_info.group = grp.getgrgid(file_stat.st_gid).gr_name
            file_info.mode = oct(file_stat.st_mode)  # & 0777
            file_info.modified = datetime.datetime \
                .fromtimestamp(file_stat.st_mtime) \
                .strftime('%Y-%m-%d %H:%M:%S')
            file_info.checksum = get_file_hash(file_info.path,
                                               hash_object.copy())

            if not file_info.checksum:
                eprint("Error: Unable to read file {}".format(file_info.path))

            yield file_info


parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description='Simple system integrity verifier.',
    epilog='Example:\n'
           '    {} -i -D /etc/ -V db.csv -R report.txt -H md5\n'
           '    {} -v -D /etc/ -V db.csv -R report.txt'.format(sys.argv[0],
                                                               sys.argv[0]))
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-i', action='store_true', dest='initiation_mode',
                   help='enable initiation mode')
group.add_argument('-v', action='store_true', dest='verification_mode',
                   help='enable verification mode')
parser.add_argument('-D', type=str, required=True, dest='monitored_directory',
                    help='directory to be monitored')
parser.add_argument('-V', type=str, required=True, dest='verification_file',
                    help='verification database file')
parser.add_argument('-R', type=str, required=True, dest='report_file',
                    help='destination of the text file report')
parser.add_argument('-H', type=str, dest='hash_function',
                    choices=SUPPORTED_HASHING_FUNCTIONS,
                    help='hashing algorithm (only for initiation mode)')

args = parser.parse_args()

if args.initiation_mode:
    print('Initiation mode.')

    if not args.hash_function:
        eprint("Error: No hashing algorithm was specified. "
               "Please use option '-H'")
        sys.exit()

    # a)
    if not os.path.exists(args.monitored_directory):
        eprint("Error: monitored directory '{}' does not exist"
               .format(args.monitored_directory))
        sys.exit()

    if not os.path.isdir(args.monitored_directory):
        eprint("Error: monitored directory '{}' is not a directory"
               .format(args.monitored_directory))
        sys.exit()

    # b)
    if is_subpath(args.monitored_directory, args.verification_file):
        eprint("Error: verification file ('{}') exists inside monitored "
               "directory ('{}')".format(args.verification_file,
                                         args.monitored_directory))
        sys.exit()

    if is_subpath(args.monitored_directory, args.report_file):
        eprint("Error: report file ('{}') exists inside monitored directory "
               "('{}')".format(args.report_file, args.monitored_directory))
        sys.exit()

    # c) is done by argument parser

    # d)
    if os.path.exists(args.verification_file):
        eprint("Error: verification file '{}' already exists"
               .format(args.verification_file))
        if not prompt_yes_no("Overwrite existing verification file?"):
            sys.exit()

    if os.path.exists(args.report_file):
        eprint("Error: report file '{}' already exists"
               .format(args.report_file))
        if not prompt_yes_no("Overwrite existing report file?"):
            sys.exit()

    # e)
    hash_object = hashlib.new(args.hash_function)
    walk_stats = WalkStats()

    with open(args.verification_file, 'w') as verification_handle:
        verification_writer = csv.writer(verification_handle)
        verification_writer.writerow([args.hash_function])

        dt_start = datetime.datetime.now()

        for file_info in walk_directory_sorted(args.monitored_directory,
                                               hash_object, walk_stats):
            verification_writer.writerow([file_info.path, file_info.size,
                                          file_info.user, file_info.group,
                                          file_info.mode, file_info.modified,
                                          file_info.checksum])

        dt_end = datetime.datetime.now()

    # f)
    elapsed_milliseconds = (dt_end - dt_start).total_seconds()

    with open(args.report_file, 'w') as f:
        f.write("Monitored directory   : {}\n"
                .format(os.path.abspath(args.monitored_directory)))
        f.write("Verification file     : {}\n"
                .format(os.path.abspath(args.verification_file)))
        f.write("Number of directories : {}\n"
                .format(walk_stats.total_directories))
        f.write("Number of files       : {}\n"
                .format(walk_stats.total_files))
        f.write("Execution time        : {}s\n"
                .format(elapsed_milliseconds))

if args.verification_mode:
    print('Verification mode.')

    # a)
    if not os.path.isfile(args.verification_file):
        eprint("Error: verification file '{}' does not exist"
               .format(args.verification_file))
        sys.exit()

    # b)
    if is_subpath(args.monitored_directory, args.verification_file):
        eprint("Error: verification file '{}' exists inside monitored "
               "directory '{}'".format(args.verification_file,
                                       args.monitored_directory))
        sys.exit()

    # c)
    if is_subpath(args.monitored_directory, args.report_file):
        eprint("Error: report file '{}' exists inside monitored "
               "directory '{}'".format(args.report_file,
                                       args.monitored_directory))
        sys.exit()

    # d)
    walk_stats = WalkStats()
    num_warnings = 0

    with open(args.verification_file, 'r') as verification_handle, \
            open(args.report_file, 'w') as report_handle:
        dt_start = datetime.datetime.now()

        iter_old = csv.reader(verification_handle)

        hash_algorithm = next(iter_old)[0]
        hash_object = hashlib.new(hash_algorithm)

        iter_new = walk_directory_sorted(args.monitored_directory,
                                         hash_object, walk_stats)

        o_file = FileInfo(*next(iter_old, []))
        n_file = next(iter_new, None)
        while o_file or n_file:
            if ((not o_file and n_file) or
                    (o_file and n_file and o_file.path > n_file.path)):
                # New file

                report_handle.write('+{} was added\n'.format(n_file.path))
                num_warnings += 1

                n_file = next(iter_new, None)
            elif ((o_file and not n_file) or
                  (o_file and n_file and o_file.path < n_file.path)):
                # File deleted

                report_handle.write('-{} was deleted\n'.format(o_file.path))
                num_warnings += 1

                o_file = FileInfo(*next(iter_old, []))
            elif o_file and n_file and o_file.path == n_file.path:
                # Same file

                if o_file.size != n_file.size:
                    report_handle.write('*{}, size: {} -> {}\n'
                                        .format(o_file.path, o_file.size,
                                                n_file.size))
                    num_warnings += 1

                if o_file.user != n_file.user:
                    report_handle.write('*{}, owner: {} -> {}\n'
                                        .format(o_file.path, o_file.user,
                                                n_file.user))
                    num_warnings += 1

                if o_file.group != n_file.group:
                    report_handle.write('*{}, group: {} -> {}\n'
                                        .format(o_file.path, o_file.group,
                                                n_file.group))
                    num_warnings += 1

                if o_file.mode != n_file.mode:
                    report_handle.write('*{}, mode: {} -> {}\n'
                                        .format(o_file.path, o_file.mode,
                                                n_file.mode))
                    num_warnings += 1

                if o_file.modified != n_file.modified:
                    report_handle.write('*{}, last modified: {} -> {}\n'
                                        .format(o_file.path, o_file.modified,
                                                n_file.modified))
                    num_warnings += 1

                if o_file.checksum != n_file.checksum:
                    report_handle.write('*{}, checksum: {} -> {}\n'
                                        .format(o_file.path, o_file.checksum,
                                                n_file.checksum))
                    num_warnings += 1


                o_file = FileInfo(*next(iter_old, []))
                n_file = next(iter_new, None)
            else:
                raise Exception("Internal logic error!")
        dt_end = datetime.datetime.now()

    # e)
        elapsed_milliseconds = (dt_end - dt_start).total_seconds()

        report_handle.write("Monitored directory   : {}\n"
                            .format(os.path.abspath(args.monitored_directory)))
        report_handle.write("Verification file     : {}\n"
                            .format(os.path.abspath(args.verification_file)))
        report_handle.write("Report file (this)    : {}\n"
                            .format(os.path.abspath(args.report_file)))
        report_handle.write("Number of directories : {}\n"
                            .format(walk_stats.total_directories))
        report_handle.write("Number of files       : {}\n"
                            .format(walk_stats.total_files))
        report_handle.write("Number of warnings    : {}\n"
                            .format(num_warnings))
        report_handle.write("Execution time        : {}s\n"
                            .format(elapsed_milliseconds))
