#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import shutil
import subprocess
import sys
from glob import glob
from pathlib import Path
from zipfile import ZipFile


def parse_sca_filename(sca_path: str):
    """
    Extracts (version, patch) from the SCA filename in the format:
      ADSSAP31_0-80000623.SCA
    Returns a tuple (version_int, patch_int).
    If parsing fails, returns (0, 0).
    """
    base_name = os.path.basename(sca_path)  # e.g., ADSSAP31_0-80000623.SCA
    # Remove the extension
    if base_name.lower().endswith(".sca"):
        base_name = base_name[:-4]  # remove .SCA

    # Look for the pattern "something_number-number"
    match = re.search(r"_(\d+)-(\d+)$", base_name)
    if match:
        version_str, patch_str = match.groups()
        try:
            return int(version_str), int(patch_str)
        except:
            pass
    return 0, 0


def get_file_list(path_folder, ext):
    """
    Returns a list of all files with the given extension (without the dot) in the specified directory (including subdirectories).
    """
    return [
        y
        for x in os.walk(path_folder)
        for y in glob(os.path.join(x[0], f"*.{ext}"))
    ]


def unpack_zip(zip_file, base_path, extract_path):
    """
    Unpacks the zip file located at base_path + zip_file into the extract_path directory.
    The name of the created directory is formed from the archive name without the extension.
    Recursively searches for nested ZIP archives within the unpacked data.
    """
    try:
        full_file_path = (
            zip_file if os.path.isabs(zip_file)
            else os.path.join(base_path, zip_file)
        )
        with ZipFile(full_file_path, 'r') as parent_archive:
            # Form the folder name by removing common extensions from the archive name:
            archive_name = os.path.basename(zip_file)
            for ext in (".zip", ".war", ".ear", ".sda", ".SCA"):
                archive_name = archive_name.replace(ext, "")

                # Destination folder for extraction
            target_dir = os.path.join(extract_path, archive_name)
            parent_archive.extractall(target_dir)
            namelist = parent_archive.namelist()

            # Recursively unpack found zip files
        for name in namelist:
            if name.lower().endswith('.zip'):
                relative_path = os.path.join(target_dir, name)
                unpack_zip(relative_path, "", target_dir)

    except Exception as ex:
        print(f"[*] ERROR unpacking {zip_file}: {ex}")


def check_any_zip_archive(path_folder):
    """
    Checks if there are any archives (sda, ear, war, zip) in the directory (including subdirectories).
    Returns True/False.
    """
    for ext in ["sda", "ear", "war", "zip"]:
        if get_file_list(path_folder, ext):
            return True
    return False


def run_decompile(path_compiled, path_out, decompiler_jar):
    """
    Runs the decompilation process using Procyon (or another) and outputs statistics.
    """
    try:
        cmd = f'java -jar "{decompiler_jar}" {path_compiled}\\* -o {path_out}'
        output = subprocess.check_output(cmd, shell=True).decode(
            sys.stdout.encoding,
            errors='ignore'
        )
        print(f"[*] Decompiled {len(output.splitlines())} files")
    except Exception as ex:
        print(f"[*] Error during decompilation: {ex}")


def copy_file_new_path(list_files, dst_base_path, new_path_folder, ext):
    """
    Copies each file from list_files to the directory dst_base_path/new_path_folder,
    renaming them to 0.ext, 1.ext, etc.
    """
    try:
        tmp_file_name = 0
        output_dir = os.path.join(dst_base_path, new_path_folder)
        for file_path in list_files:
            new_name = f"{tmp_file_name}.{ext}"
            shutil.copy2(file_path, os.path.join(output_dir, new_name))
            tmp_file_name += 1
    except Exception as ex:
        print(f"[*] Error copying files: {ex}")


def expand_sca(sca_path, output_folder):
    """
    Unpacks the given sca_path (SCA archive) into output_folder,
    then recursively extracts nested zip/war/ear/sda, etc.
    """
    print(f"[*] Unpacking {os.path.basename(sca_path)} into {output_folder}")
    unpack_zip(sca_path, "", output_folder)

    # Continue unpacking as long as archives are found within
    while check_any_zip_archive(output_folder):
        for ext in ["sda", "ear", "war", "zip"]:
            items = get_file_list(output_folder, ext)
            if items:
                print(f"[*] Unzipping {ext.upper()}. Found {len(items)} files.")
            for item in items:
                unpack_zip(item, "", output_folder)
                os.remove(item)


def main():
    # 1. Get paths and create necessary directories
    input_path = input("Write path to SCA files folder:\n").strip()
    input_decompiler = input(
        "Write here path to Procyon jar (Press ENTER for default path: C:\\dec\\d.jar)\n"
    ) or r"C:\dec\d.jar"

    list_of_folders = [
        "old", "new", "old_jar", "old_class", "new_jar", "new_class"
    ]
    # Create/Clear directories for unpacking
    for folder in list_of_folders:
        dir_path = os.path.join(input_path, folder)
        if os.path.exists(dir_path):
            shutil.rmtree(dir_path, ignore_errors=True)
        Path(dir_path).mkdir(parents=True, exist_ok=True)

        # 2. Search for SCA files in the root directory
    sca_files = get_file_list(input_path, "SCA")

    # If fewer than 2 files are found, warn the user
    if len(sca_files) < 2:
        print("[*] Fewer than two SCA files found. At least two are required for comparison.")
        return

        # 3. Parse versions and patches, then sort
    parsed = []
    for sca in sca_files:
        version, patch = parse_sca_filename(sca)
        parsed.append((sca, version, patch))

        # Sort by (version, patch) – oldest first, newest last
    parsed.sort(key=lambda x: (x[1], x[2]))

    # Select the oldest and newest files
    old_sca_path, old_ver, old_patch = parsed[0]
    new_sca_path, new_ver, new_patch = parsed[-1]

    print(f"[*] Oldest file: {os.path.basename(old_sca_path)} (ver={old_ver}, patch={old_patch})")
    print(f"[*] Newest file: {os.path.basename(new_sca_path)} (ver={new_ver}, patch={new_patch})")

    # 4. Unpack old -> folder old, new -> folder new
    old_output_dir = os.path.join(input_path, "old")
    new_output_dir = os.path.join(input_path, "new")

    expand_sca(old_sca_path, old_output_dir)
    expand_sca(new_sca_path, new_output_dir)

    # 5. Copy jar/class from old => old_jar / old_class; new => new_jar / new_class
    old_jar_list = get_file_list(old_output_dir, "jar")
    copy_file_new_path(old_jar_list, input_path, "old_jar", "jar")
    print(f"[*] Copied {len(old_jar_list)} JAR files from old folder to old_jar.")

    old_class_list = get_file_list(old_output_dir, "class")
    copy_file_new_path(old_class_list, input_path, "old_class", "class")
    print(f"[*] Copied {len(old_class_list)} CLASS files from old folder to old_class.")

    new_jar_list = get_file_list(new_output_dir, "jar")
    copy_file_new_path(new_jar_list, input_path, "new_jar", "jar")
    print(f"[*] Copied {len(new_jar_list)} JAR files from new folder to new_jar.")

    new_class_list = get_file_list(new_output_dir, "class")
    copy_file_new_path(new_class_list, input_path, "new_class", "class")
    print(f"[*] Copied {len(new_class_list)} CLASS files from new folder to new_class.\n")

    # 6. Decompile everything
    print("[*] Starting decompilation of old_jar files")
    run_decompile(os.path.join(input_path, "old_jar"), os.path.join(input_path, "out_old"), input_decompiler)
    print("[*] Finished decompiling old_jar files\n")

    print("[*] Starting decompilation of new_jar files")
    run_decompile(os.path.join(input_path, "new_jar"), os.path.join(input_path, "out_new"), input_decompiler)
    print("[*] Finished decompiling new_jar files\n")

    print("[*] Starting decompilation of old_class files")
    run_decompile(os.path.join(input_path, "old_class"), os.path.join(input_path, "out_old"), input_decompiler)
    print("[*] Finished decompiling old_class files\n")

    print("[*] Starting decompilation of new_class files")
    run_decompile(os.path.join(input_path, "new_class"), os.path.join(input_path, "out_new"), input_decompiler)
    print("[*] Finished decompiling new_class files\n")

    # 7. Copy *.jsp to out_old and out_new
    old_jsp_list = get_file_list(old_output_dir, "jsp")
    copy_file_new_path(old_jsp_list, input_path, "out_old", "jsp")
    print(f"[*] Copied {len(old_jsp_list)} JSP files from old folder to out_old.")

    new_jsp_list = get_file_list(new_output_dir, "jsp")
    copy_file_new_path(new_jsp_list, input_path, "out_new", "jsp")
    print(f"[*] Copied {len(new_jsp_list)} JSP files from new folder to out_new.\n")

    print(
        "[*] All tasks completed. You can now select the out_old and out_new folders using DiffDoG (or another comparison tool) to find vulnerabilities.")
    print("[*] Happy hacking!")


if __name__ == "__main__":
    main()
