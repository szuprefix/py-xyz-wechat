# -*- coding:utf-8 -*-

GENDER_UNDEFINED = '-'
GENDER_MALE = 'M'
GENDER_FEMALE = 'F'

CHOICES_GENDER = (
    (GENDER_MALE, u"男"),
    (GENDER_FEMALE, u"女"),
)

MESSAGE_TYPE_TEXT = "text"
MESSAGE_TYPE_IMAGE = "image"
MESSAGE_TYPE_SHORTVIDEO = "shortvideo"
MESSAGE_TYPE_VOICE = "voice"
MESSAGE_TYPE_VIDEO = "video"
MESSAGE_TYPE_EVENT = "event"
MESSAGE_TYPE_LOCATION = "location"

CHOICES_MESSAGE_TYPE = (
    (MESSAGE_TYPE_TEXT, u"文本"),
    (MESSAGE_TYPE_IMAGE, u"图片"),
    (MESSAGE_TYPE_SHORTVIDEO, u"小视频"),
    (MESSAGE_TYPE_VOICE, u"语音"),
    (MESSAGE_TYPE_VIDEO, u"视频"),
    (MESSAGE_TYPE_EVENT, u"事件"),
    (MESSAGE_TYPE_LOCATION, u"地理位置")
)
