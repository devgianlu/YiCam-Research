from dataclasses import dataclass


@dataclass
class AVFrame:
    codec_id: int
    flags: int
    live_flag: int
    online_num: int
    use_count: int
    frame_num: int
    video_width: int
    video_height: int
    timestamp: int
    is_day: int
    cover_state: int
    out_loss: int
    in_loss: int
    timestamp_ms: int
    frame_data: bytes

    @staticmethod
    def parse(data: bytes):
        return AVFrame(
            int.from_bytes(data[0:2], 'big'), data[2], data[3], data[4], data[5], int.from_bytes(data[6:8], 'big'),
            int.from_bytes(data[8:10], 'big'), int.from_bytes(data[10:12], 'big'), int.from_bytes(data[12:16], 'big'),
            data[16], data[17], data[18], data[19], int.from_bytes(data[20:24], 'big'), bytearray(data[24:])
        )

    def is_iframe(self):
        return (self.flags & 1) == 1

    def is_covered(self):
        return self.cover_state == 1

    def is_live(self):
        return (self.live_flag & 1) == 1

    def is_privacy_mode(self):
        return (self.live_flag & 2) == 1
