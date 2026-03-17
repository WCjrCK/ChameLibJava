package utils;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Objects;

public final class Serializer {
    private Serializer() {}

    public static byte[] pack(byte[]... fields) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            for (byte[] field : fields) writeBytes(out, field);
            return out.toByteArray();
        } catch (Exception e) {
            throw new IllegalArgumentException("序列化失败", e);
        }
    }

    public static byte[] encodeBigInteger(BigInteger value) {
        return Objects.requireNonNull(value, "BigInteger 不能为空").toByteArray();
    }

    public static void writeBytes(ByteArrayOutputStream out, byte[] data) {
        Objects.requireNonNull(out, "输出流不能为空");
        byte[] field = Objects.requireNonNull(data, "字段不能为空");
        writeInt(out, field.length);
        out.writeBytes(field);
    }

    public static void writeInt(ByteArrayOutputStream out, int value) {
        Objects.requireNonNull(out, "输出流不能为空");
        out.writeBytes(ByteBuffer.allocate(Integer.BYTES).putInt(value).array());
    }

    public static final class Reader {
        private final ByteBuffer buffer;

        public Reader(byte[] data) {
            this.buffer = ByteBuffer.wrap(Objects.requireNonNull(data, "字节流不能为空"));
        }

        public byte[] readBytes() {
            int len = readInt();
            if (len < 0 || len > buffer.remaining()) {
                throw new IllegalArgumentException("无效字段长度: " + len);
            }
            byte[] data = new byte[len];
            buffer.get(data);
            return data;
        }

        public BigInteger readBigInteger() {
            return new BigInteger(readBytes());
        }

        public void ensureFullyConsumed() {
            if (buffer.hasRemaining()) {
                throw new IllegalArgumentException("字节流存在未消费数据");
            }
        }

        private int readInt() {
            if (buffer.remaining() < Integer.BYTES) {
                throw new IllegalArgumentException("字节流长度不足");
            }
            return buffer.getInt();
        }
    }
}
