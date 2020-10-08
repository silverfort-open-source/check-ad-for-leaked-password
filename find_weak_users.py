#!/usr/bin/env python3

import csv
import sys
import argparse
import os
from tqdm import tqdm
import xlsxwriter
import re


def search_leaked_hashes(ntds_dict, nthash_path):
    leaked_pass_list = []
    if nthash_path is None or not os.path.exists(nthash_path):
        print("Leaked password file not found")
        sys.exit(1)

    with open(nthash_path, 'rt') as f:
        dialect = csv.Sniffer().sniff(f.read(1024))
        f.seek(0)
        reader = csv.reader(f, dialect)
        first_line = next(reader)
        f.seek(0)
        # check if file in right format
        if len(first_line) != 2 or len(first_line[0]) != 32 or not first_line[0].isalnum() or \
                not first_line[1].isdecimal():
            print("leaked password file unknown format")
            sys.exit(1)

        with tqdm(unit='B', unit_scale=True, total=os.path.getsize(nthash_path)) as pbar:
            # for row in reader:
            #    pbar.update(len(row[0]) + len(row[1]) + len(dialect.lineterminator))
            #    nthash = row[0].upper()
            #    if nthash in ntds_dict:
            #        leaked_pass_list.append([ntds_dict[nthash], row[1]])
            for line in f:
                pbar.update(len(line))
                nthash = line[:32]
                if nthash in ntds_dict:
                    try:
                        leaked_pass_list.append(
                            [ntds_dict[nthash], line.split(':')[-1].split(dialect.lineterminator)[0]])
                    except IndexError:
                        print("leaked password file unknown format")
                        sys.exit(1)
    return leaked_pass_list


def find_duplicate_passwords(ntds_dict):
    dup_pass_list = []
    for users in ntds_dict.values():
        if len(users) > 1:  # more then 1 user per nthash
            dup_pass_list = dup_pass_list + users
    return dup_pass_list


def secretsdump_stdin_to_dict(stdin=sys.stdin):
    ntds_dict = {}
    for line in stdin:
        for match in re.findall(".*:\\d*:[a-z0-9]*:[a-z0-9]{32}:::", line):
            row = match.split(":")
            username = row[0]
            nthash = row[3].upper()
            if nthash in ntds_dict:
                ntds_dict[nthash].append(username)
            else:
                ntds_dict[nthash] = [username, ]
    return ntds_dict


def ntds_file_to_dict(ntds_path, ntds_format=None):
    if ntds_path is None or not os.path.exists(ntds_path):
        print("ntds dump not found!")
        sys.exit(1)
    ntds_dict = {}
    with open(ntds_path, 'rt') as f:
        dialect = csv.Sniffer().sniff(f.read(1024))
        f.seek(0)
        reader = csv.reader(f, dialect)
        first_line = next(reader)
        f.seek(0)
        # try to auto detect ntds format
        if ntds_format is None:
            if len(first_line) == 7 and len(first_line[3]) == 32 and first_line[3].isalnum():
                ntds_format = 'secretsdump'
            elif len(first_line) == 2 and len(first_line[1]) == 32 and first_line[1].isalnum():
                ntds_format = 'hashcat'
            else:
                print("cant detect ntds dump file format")
                sys.exit(1)
        for row in reader:
            if ntds_format == 'secretsdump':
                username = row[0]
                nthash = row[3].upper()
            elif ntds_format == 'hashcat':
                username = row[0]
                nthash = row[1].upper()
            if len(nthash) != 32:
                print("nthash dump parsing problem, skipping user")
                continue
            else:
                if nthash in ntds_dict:
                    ntds_dict[nthash].append(username)
                else:
                    ntds_dict[nthash] = [username, ]
    return ntds_dict


def print_leaked(leaked_pass_list):
    print("Found {} users with leaked passwords".format(sum([len(x[0]) for x in leaked_pass_list])))
    for line in leaked_pass_list:
        for user in line[0]:
            print(user, ", leak prevalence: ", line[1])


def xlsx_export(xlsx_path, dup_pass_list, leaked_pass_list):
    workbook = xlsxwriter.Workbook(xlsx_path)
    # leaked password
    worksheet = workbook.add_worksheet("Users With Leaked Password")
    bold = workbook.add_format({'bold': True})
    worksheet.write(0, 0, "Username", bold)
    worksheet.write(0, 1, "Prevalence", bold)
    row = 1
    for user_group in leaked_pass_list:
        for user in user_group[0]:
            worksheet.write(row, 0, user)
            worksheet.write(row, 1, user_group[1])
            row += 1

    # duplicated password
    worksheet = workbook.add_worksheet("Users With Duplicated Password")
    bold = workbook.add_format({'bold': True})
    worksheet.write(0, 0, "Username", bold)
    row = 1
    for user in dup_pass_list:
        worksheet.write(row, 0, user)
        row += 1
    workbook.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=True,
                                     description="Simple tool to compare ntds dump with leaked nthash file")
    parser.add_argument('--ntds-file', action='store', help="Path of ntds secrets dump")
    parser.add_argument('--nthash-file', action='store', help="Path of leaked nthash list file")
    parser.add_argument('--ntds-format', choices=['hashcat', 'secretsdump'],
                        help="The format of the ntds dump, hashcat or secretsdump.py. if not specified try to detect automatically")
    parser.add_argument('--stdin', action='store_true', default=False, help="Get ntds secrets dump from stdin")
    parser.add_argument('--export-xlsx', action='store', help="Path where to save the result as Excel file")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    if args.stdin:
        print("Loading ntds hashes from stdin")
        ntds_dict = secretsdump_stdin_to_dict()
    else:
        print("Loading ntds hashes from file")
        ntds_dict = ntds_file_to_dict(args.ntds_file, args.ntds_format)
    if len(ntds_dict) <= 0:
        print("Extracted 0 ntds hashes, exiting")
        sys.exit(1)
    print("Search for users with duplicate passwords")
    dup_pass_list = find_duplicate_passwords(ntds_dict)
    print("Search for users with leaked passwords")
    leaked_pass_list = search_leaked_hashes(ntds_dict, args.nthash_file)
    if args.export_xlsx is None:
        print_leaked(leaked_pass_list)
    else:
        print("Export to xlsx file")
        xlsx_export(args.export_xlsx, dup_pass_list, leaked_pass_list)
    print("Done!")
