#!/bin/bash
#First instance running always casts a crawling_stats.py
#Second instance or more is always a crawling_elk.py
mkdir -p pdfs
mkdir -p midis
mkdir -p audios
mkdir -p images/nsfw
mkdir -p images/sfw
while (test 1)
do
	(
            flock -n 200 || exit 1
            ./crawling_stats.py
        ) 200>/tmp/crawling_stats.lock
	#./crawling2elk.py 2>/dev/null
	unbuffer ./crawling2elk.py 2>&1 | grep -vE 'external/local_xla/xla/tsl/cuda/cudart_stub.cc:32|external/local_xla/xla/stream_executor/cuda/cuda_fft.cc:467|cuda_dnn.cc:8579|cuda_dnn.cc:8579|cuda_blas.cc:1407|computation_placer.cc:177|WARNING: All log messages before absl|tensorflow/core/platform/cpu_feature_guard.cc:210|To enable the following instructions: AVX2, in other operations, rebuild TensorFlow with the appropriate compiler flags.|external/local_xla/xla/stream_executor/cuda/cuda_platform.cc:51'
	sleep .1
done
