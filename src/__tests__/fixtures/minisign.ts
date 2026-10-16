/**
 * Made by minisign 0.11 (`minisign -G -W`, then `minisign -S` on the file "hello world\n"): an unencrypted key, a signature in the
 * default (BLAKE2b-hashed, "ED") form with a trusted comment, and one in the legacy form (`-l`, "Ed"). `minisign -V` accepts them.
 */
export const MS_SEED = 'f1ac93937869f682a585b20db4be66d84ff090c82f42914e69952c649a32c75e';
export const MS_PUBLIC_HEX = '5df88394ef8e942e51a3df4b20ca853a3c769d8e94cf580f3826db89076f2926';
export const MS_KEY_ID = 'B74960C202F410C9';
export const MS_PUBLIC_FILE = 'untrusted comment: minisign public key B74960C202F410C9\nRWTJEPQCwmBJt134g5TvjpQuUaPfSyDKhTo8dp2OlM9YDzgm24kHbykm\n';
export const MS_PUBLIC_LINE = 'RWTJEPQCwmBJt134g5TvjpQuUaPfSyDKhTo8dp2OlM9YDzgm24kHbykm';
export const MS_MESSAGE = 'hello world\n';
export const MS_TRUSTED_COMMENT = 'timestamp:1700000000\tfile:msg.txt';
export const MS_SIG_HASHED =
    'untrusted comment: signature from minisign secret key\nRUTJEPQCwmBJt1+ho+eXhWVFgLEF3cIAf1KYknPR+0wnBDrSAOc0dX6/6zfCPVq2btUddi6bxZ+d1ill9L/KIE3hUWANdJywcgo=\ntrusted comment: timestamp:1700000000\tfile:msg.txt\n4Z9h8bxCC1lNqEdCSrAPwD8Of9rHLqWq/JWt7Ckn7S4wg0IhKDcgiISy4mejS5me/EKLlbhptrAN0lTh5AvPAA==\n';
export const MS_SIG_LEGACY =
    'untrusted comment: signature from minisign secret key\nRWTJEPQCwmBJtx3h7m6cUL7+aIl1v3uuE+mu8hjAfoGsuZH0RJxCCBvNJjuvb0SA5YAZBKq8AD84FGU+Rict3kIaQ2Z2nKuAcgY=\ntrusted comment: legacy one\neSHtuzBqUO+7uYe7nX90XkbRDuPesCjh7edvpj/IJSOHc1YdSfBczgXi2yquCemvjVK1pfKkqCRDT4b7tKMkCA==\n';
