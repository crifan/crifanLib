#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Filename: crifanMultimedia.py
Function: crifanLib's python multimedia (audio, video) related functions
Version: v20181122
Note:
1. latest version and more can found here:
https://github.com/crifan/crifanLib/blob/master/python/crifanLib
"""

__author__ = "Crifan Li (admin@crifan.com)"
__version__ = "v20181122"
__copyright__ = "Copyright (c) 2018, Crifan Li"
__license__ = "GPL"

import os
from crifanLib.crifanSystem import runCommand

################################################################################
# Config
################################################################################

################################################################################
# Constant
################################################################################
CURRENT_LIB_FILENAME = "crifanMultimedia"

################################################################################
# Global Variable
################################################################################
gVal = {
}

gConst = {
}

################################################################################
# Internal Function
################################################################################


################################################################################
# Python Multimedia Function
################################################################################


def formatFfmpegTimeStr(timeValue, seperatorHms=":", seperatorMs="."):
    """
        (1) format time to 00:00:03.110, for pass into ffmpeg to use:
            ffmpeg -i show_65586_video.mp4 -ss 00:00:03.110 -to 00:00:06.110 -b:a 128k extracted_audio_segment.mp3
        (2) also use format to 000003110, used for normal file name:
            audio_000003110_000006110.mp3

        Note:
            timeValue is class of datetime.time, NOT time
    """
    millisecond = int(timeValue.microsecond / 1000)
    ffmpegTimeStr = "%02d%s%02d%s%02d%s%03d" % (
        timeValue.hour, seperatorHms,
        timeValue.minute, seperatorHms,
        timeValue.second, seperatorMs,
        millisecond)
    return ffmpegTimeStr

def splitAudio(
        inputAudioFullPath,
        startTime,
        endTime,
        outputAudioFullPath="",
        isOutputLog=False,
        isAskOverwrite=False,
    ):
    """
        split specified time duration(startTime - endTime) auido (default mp3) file from input (whole) audio (normally .mp4) file
        Note:
            internal using ffmpeg, your system must installed ffmpeg

        params:
        * `inputAudioFullPath`: /whole/audio/path/input_audio_name.mp3
        * `startTime`: start time of type datetime.time
        * `endTime`: end time of type datetime.time
        * `outputAudioFullPath`:
            * `""`: -> /whole/audio/path/ + input_audio_name_{startTime}_{endTime}.mp3
            * `"/output/audio/path/output_audio_name.mp3"`: /output/audio/path/output_audio_name.mp3
        * `isOutputLog`: ffmpeg show console log or not
            if not, will redirect to null device to omit it
        * `isAskOverwrite`: when existed file, whether ask overwrite or not
            default Not ask, that is force overwrite

        return: (bool, str, str)
                    bool: extract OK or not
                    str: splitted audio full path
                    str: error message string
    """
    extractIsOk = False
    splittedAudioFullPath = ""
    errMsg = "Unknown Error"

    if not outputAudioFullPath:
        inputAudioPath = os.path.dirname(inputAudioFullPath)
        inputAudioName = os.path.basename(inputAudioFullPath)
        inputAudioNameNoSuffix, inputAudioSuffix = os.path.splitext(inputAudioName) # 'show_14322648_audio', '.mp3'

        startTimeStrForName = formatFfmpegTimeStr(startTime, "", "")
        endTimeStrForName = formatFfmpegTimeStr(endTime, "", "")
        timeDurationStr = "_" + startTimeStrForName + "_" + endTimeStrForName

        audioFilename = inputAudioNameNoSuffix + timeDurationStr + inputAudioSuffix # 'show_14322648_audio_000004237_000006336.mp3'
        outputAudioFullPath = os.path.join(inputAudioPath, audioFilename)

    startTimeStrFfmpeg = formatFfmpegTimeStr(startTime)
    endTimeStrFfmpeg = formatFfmpegTimeStr(endTime)
    timeDurationPara = "-ss %s -to %s" % (startTimeStrFfmpeg, endTimeStrFfmpeg) # '-ss 00:00:04.237 -to 00:00:06.336'

    extraPara = ""
    if not isAskOverwrite:
        extraPara += "-y"

    redirectOutputPara = ""
    if not isOutputLog:
        redirectOutputPara += "2> /dev/null"

    ffmpegCmd = "ffmpeg %s -i %s %s -b:a 128k %s %s" % (
        extraPara, inputAudioFullPath, timeDurationPara, outputAudioFullPath, redirectOutputPara)
    # print("ffmpegCmd=%s" % ffmpegCmd)

    # Example:
    # ffmpeg -y -i /xxx/show_14322648_audio.mp3 -ss 00:00:04.237 -to 00:00:06.336 -b:a 128k /xxx/show_14322648_audio_000004237_000006336.mp3 2> /dev/null

    extractIsOk, errMsg = runCommand(ffmpegCmd)
    if extractIsOk:
        splittedAudioFullPath = outputAudioFullPath

    return extractIsOk, splittedAudioFullPath, errMsg


def extractAudioFromVideo(
        videoFullPath,
        startTime=None,
        endTime= None,
        audioFullPath="",
        audioType="mp3",
        isOutputLog=False,
        isAskOverwrite=False,
    ):
    """
        extract specified time duration(startTime - endTime) auido (default mp3) file from video(.mp4) file
        Note:
            if startTime and endTime not specified, will ouput whole file audio
            internal using ffmpeg do convertion from mp4 to audio

        params:
        * `videoFullPath`: /video/path/video_name.mp4
        * `startTime`: start time of type datetime.time
        * `endTime`: end time of type datetime.time
        * `audioFullPath`:
            * `""`: -> /video/path/ + generated_audio_name.mp3
            * `"/audio/path/audio_name.mp3"`: /audio/path/audio_name.mp3
        * `isOutputLog`: ffmpeg show console log or not
            if not, will redirect to null device to omit it
        * `isAskOverwrite`: when existed file, whether ask overwrite or not
            default Not ask, that is force overwrite

        return: (bool, str, str)
                    True/False, audio path, error message string
    """
    extractIsOk = False
    extractedAudioPath = ""
    errMsg = "Unknown Error"

    if not audioFullPath:
        videoPath = os.path.dirname(videoFullPath)
        videoName = os.path.basename(videoFullPath)
        videoNameNoSuffix, videoSuffix = os.path.splitext(videoName) # 'show_14322648_video', '.mp4'

        timeDurationStr = ""
        if startTime and endTime:
            startTimeStrForName = formatFfmpegTimeStr(startTime, "", "")
            endTimeStrForName = formatFfmpegTimeStr(endTime, "", "")
            timeDurationStr = "_" + startTimeStrForName + "_" + endTimeStrForName

        audioFilename = videoNameNoSuffix + timeDurationStr + "." + audioType # 'show_14322648_video.mp3'
        audioFullPath = os.path.join(videoPath, audioFilename)

    timeDurationPara = ""
    if startTime and endTime:
        startTimeStrFfmpeg = formatFfmpegTimeStr(startTime)
        endTimeStrFfmpeg = formatFfmpegTimeStr(endTime)
        timeDurationPara = "-ss %s -to %s" % (startTimeStrFfmpeg, endTimeStrFfmpeg)

    extraPara = ""
    if not isAskOverwrite:
        extraPara += "-y"

    redirectOutputPara = ""
    if not isOutputLog:
        redirectOutputPara += "2> /dev/null"

    ffmpegCmd = "ffmpeg %s -i %s %s -b:a 128k %s %s" % (
        extraPara, videoFullPath, timeDurationPara, audioFullPath, redirectOutputPara)
    # print("ffmpegCmd=%s" % ffmpegCmd)

    # Example:
    # ffmpeg -y -i show_65586_video.mp4 -ss 00:00:03.110 -to 00:00:06.110 -b:a 128k show_65586_audio_000003110_000006110.mp3 2> /dev/null
    # ffmpeg -y -i /xxx/show_13304984_video.mp4 -ss 00:00:00.104 -to 00:00:04.566 -b:a 128k /xxx/user/5253/show/13304984/show_13304984_audio_000000104_000004566.mp3 2> /dev/null
    # ffmpeg -y -i show_65586_video.mp4 -b:a 128k show_65586_audio.mp3 2> /dev/null

    extractIsOk, errMsg = runCommand(ffmpegCmd)
    if extractIsOk:
        extractedAudioPath = audioFullPath

    return extractIsOk, extractedAudioPath, errMsg

################################################################################
# Test
################################################################################


if __name__ == '__main__':
    print("[crifanLib-%s] %s" % (CURRENT_LIB_FILENAME, __version__))