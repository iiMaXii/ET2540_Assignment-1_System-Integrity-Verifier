#!/usr/bin/env python3

import argparse
import csv
import datetime
import grp
import hashlib
import os
import pwd
import stat
import sys

# SUPPORTED_HASHING_FUNCTIONS = list(hashlib.algorithms_available)
SUPPORTED_HASHING_FUNCTIONS = list(hashlib.algorithms_guaranteed)


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

    for root, dirs, files in sorted(os.walk(path)):
        walk_stats_object.total_directories += 1
        walk_stats_object.total_files += len(files)
        print(root)
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

            yield file_info


parser = argparse.ArgumentParser(
    description='Simple system integrity verifier.')
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

sys.exit()

if args.initiation_mode:
    print('Initiation mode.')

    if not args.hash_function:
        print("Error: No hashing algorithm was specified."
              "Please use option '-H'")
        sys.exit()

    # a)
    if not os.path.exists(args.monitored_directory):
        print("Error: monitored directory '{}' does not exist"
              .format(args.monitored_directory))
        sys.exit()

    if not os.path.isdir(args.monitored_directory):
        print("Error: monitored directory '{}' is not a directory"
              .format(args.monitored_directory))
        sys.exit()

    # b)
    if is_subpath(args.monitored_directory, args.verification_file):
        print("Error: verification file ('{}') exists inside monitored "
              "directory ('{}')".format(args.verification_file,
                                        args.monitored_directory))
        sys.exit()

    if is_subpath(args.monitored_directory, args.report_file):
        print("Error: report file ('{}') exists inside monitored directory "
              "('{}')".format(args.report_file,
                              args.monitored_directory))
        sys.exit()

    # c) is done by argument parser

    # d)
    if os.path.exists(args.verification_file):
        print("Error: verification file '{}' already exists"
              .format(args.verification_file))
        if not prompt_yes_no("Overwrite existing verification file?"):
            sys.exit()

    if os.path.exists(args.report_file):
        print("Error: report file '{}' already exists"
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
            if not file_info.checksum and not os.path.isdir(file_info.path):
                print('Error when reading file {}'.format(file_info.path))
            verification_writer.writerow([file_info.path, file_info.size,
                                          file_info.user, file_info.group,
                                          file_info.mode, file_info.modified,
                                          file_info.checksum])

        dt_end = datetime.datetime.now()

    # f)
    elapsed_milliseconds = (dt_end - dt_start).microseconds / 1000

    with open(args.report_file, 'w') as f:
        f.write("Monitored directory  : {}\n"
                .format(os.path.abspath(args.monitored_directory)))
        f.write("Verification file    : {}\n"
                .format(os.path.abspath(args.verification_file)))
        f.write("Number of directories: {}\n"
                .format(walk_stats.total_directories))
        f.write("Number of files      : {}\n"
                .format(walk_stats.total_files))
        f.write("Execution time       : {} ms\n"
                .format(elapsed_milliseconds))

if args.verification_mode:
    print('Verification mode.')

    # a)
    if not os.path.isfile(args.verification_file):
        print("Error: verification file '{}' does not exist"
              .format(args.monitored_directory))
        sys.exit()

    # b)
    if is_subpath(args.monitored_directory, args.verification_file):
        print("Error: verification file ('{}') exists inside monitored "
              "directory ('{}')".format(args.verification_file,
                                        args.monitored_directory))
        sys.exit()

    # c)
    if is_subpath(args.monitored_directory, args.report_file):
        print("Error: report file ('{}') exists inside monitored"
              "directory ('{}')".format(args.report_file,
                                        args.monitored_directory))
        sys.exit()

    # d)
    walk_stats = WalkStats()

    with open(args.verification_file, 'r') as verification_handle:
        dt_start = datetime.datetime.now()

        iter_old = csv.reader(verification_handle)

        hash_algorithm = next(iter_old)[0]
        hash_object = hashlib.new(hash_algorithm)

        iter_new = walk_directory_sorted(args.monitored_directory,
                                         hash_object, walk_stats)

        o_file = FileInfo(*next(iter_old, []))
        n_file = next(iter_new, None)
        while o_file or n_file:
            if (n_file and not n_file.checksum and
                    not os.path.isdir(n_file.path)):
                print('Error when reading file {}'.format(n_file.path))

            if ((not o_file and n_file) or
                (o_file and n_file and o_file.path > n_file.path)):
                # New file

                print('+{} was added'.format(n_file.path))

                n_file = next(iter_new, None)
            elif ((o_file and not n_file) or
                  (o_file and n_file and o_file.path < n_file.path)):
                # File deleted

                print('-{} was deleted'.format(o_file.path))

                o_file = FileInfo(*next(iter_old, []))
            elif o_file and n_file and o_file.path == n_file.path:
                # Same file

                if o_file.size != n_file.size:
                    print('*{}, size: {} -> {}'.format(o_file.path,
                                                       o_file.size,
                                                       n_file.size))

                if o_file.user != n_file.user:
                    print('*{}, owner: {} -> {}'.format(o_file.path,
                                                        o_file.user,
                                                        n_file.user))

                if o_file.group != n_file.group:
                    print('*{}, group: {} -> {}'.format(o_file.path,
                                                        o_file.group,
                                                        n_file.group))

                if o_file.mode != n_file.mode:
                    print('*{}, mode: {} -> {}'.format(o_file.path,
                                                       o_file.mode,
                                                       n_file.mode))

                if o_file.modified != n_file.modified:
                    print('*{}, last modified: {} -> {}'
                          .format(o_file.path, o_file.modified,
                                  n_file.modified))

                if o_file.checksum != n_file.checksum:
                    print('*{}, checksum: {} -> {}'.format(o_file.path,
                                                           o_file.checksum,
                                                           n_file.checksum))

                o_file = FileInfo(*next(iter_old, []))
                n_file = next(iter_new, None)
            else:
                raise Exception("Internal logic error!")
        dt_end = datetime.datetime.now()

    # e)
    elapsed_milliseconds = (dt_end - dt_start).microseconds / 1000

    print('{} ms'.format(elapsed_milliseconds))
    print(walk_stats.total_directories)
    print(walk_stats.total_files)
