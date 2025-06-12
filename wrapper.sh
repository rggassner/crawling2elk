#!/bin/bash

#
# Web Crawler Orchestration Script
#
# DESCRIPTION:
#     This script sets up the directory structure for a web crawling system and runs
#     the main crawler in a continuous loop with output filtering. The crawler system
#     support multiple instance types with different responsibilities:
#     - Instance 1: HTTPS server, housekeeping, and crawling
#     - Instance 2: Fast crawler using requests library  
#     - Instance 3: IP/port scanner
#     - Instance 4+: Regular crawlers
#
# DIRECTORY STRUCTURE:
#     Creates organized directories for different types of crawled content:
#     - pdfs/              - PDF documents
#     - midis/             - MIDI audio files
#     - audios/            - Audio files
#     - images/nsfw/       - NSFW images
#     - images/sfw/        - Safe-for-work images
#     - compressed/        - Archive files (ZIP, RAR, etc.)
#     - docs/              - Document files
#     - fonts/             - Font files
#     - torrents/          - Torrent files
#     - input_url_files/   - URL input files
#     - databases/         - Database files
#
# EXECUTION:
#     Runs crawling2elk.py in an infinite loop with:
#     - Unbuffered output for real-time logging
#     - Filtered stderr/stdout to remove TensorFlow/CUDA noise
#     - 0.1 second sleep between iterations to prevent excessive CPU usage
#
# OUTPUT FILTERING:
#     Suppresses common TensorFlow/CUDA warning messages that don't affect
#     crawler functionality, including GPU library warnings and CPU optimization
#     suggestions.
#
# USAGE:
#     ./script_name.sh
#
# REQUIREMENTS:
#     - crawling2elk.py must be executable and in the same directory
#     - unbuffer command (from expect package)
#     - Standard Unix utilities (mkdir, grep, sleep, test)
#
# NOTES:
#     The script runs indefinitely until manually terminated (Ctrl+C).
#     All crawler output is displayed in real-time except for filtered messages.
#

mkdir -p pdfs
mkdir -p midis
mkdir -p audios
mkdir -p images/nsfw
mkdir -p images/sfw
mkdir -p compressed
mkdir -p docs
mkdir -p fonts
mkdir -p torrents
mkdir -p input_url_files
mkdir -p databases
while (test 1)
do
	unbuffer ./crawling2elk.py 2>&1 | grep -vE 'external/local_xla/xla/tsl/cuda/cudart_stub.cc:32|external/local_xla/xla/stream_executor/cuda/cuda_fft.cc:467|cuda_dnn.cc:8579|cuda_dnn.cc:8579|cuda_blas.cc:1407|computation_placer.cc:177|WARNING: All log messages before absl|tensorflow/core/platform/cpu_feature_guard.cc:210|To enable the following instructions: AVX2, in other operations, rebuild TensorFlow with the appropriate compiler flags.|external/local_xla/xla/stream_executor/cuda/cuda_platform.cc:51'
	sleep .1
done
