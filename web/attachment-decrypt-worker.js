importScripts('nacl-fast.min.js');
function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
self.onmessage = (event) => {
  const data = event.data || {};
  const id = data.id;
  try {
    const packedB64 = new TextDecoder().decode(new Uint8Array(data.packedBuffer));
    const packed = base64ToBytes(packedB64.trim());
    const key = new Uint8Array(data.keyBuffer);
    const nonceLength = nacl.secretbox.nonceLength;
    if (packed.length <= nonceLength) {
      self.postMessage({ id, plainBuffer: null });
      return;
    }
    const plain = nacl.secretbox.open(
      packed.subarray(nonceLength),
      packed.subarray(0, nonceLength),
      key
    );
    if (!plain) {
      self.postMessage({ id, plainBuffer: null });
      return;
    }
    const plainBuffer = plain.buffer.slice(plain.byteOffset, plain.byteOffset + plain.byteLength);
    self.postMessage({ id, plainBuffer }, [plainBuffer]);
  } catch (error) {
    self.postMessage({
      id,
      error: (error && error.message) || 'Не удалось расшифровать вложение',
    });
  }
};