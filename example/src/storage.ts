import AsyncStorage from '@react-native-async-storage/async-storage';
import * as Keychain from 'react-native-keychain';
import {
  createEncryptedStorage,
  loadOrCreateIdentity,
  type KeyValueStorage,
} from 'fprot';

export const secureStorage: KeyValueStorage = {
  async getItem(key) {
    const credentials = await Keychain.getGenericPassword({ service: key });
    return credentials ? credentials.password : null;
  },
  async setItem(key, value) {
    const result = await Keychain.setGenericPassword('fprot', value, {
      service: key,
      accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
    });
    if (!result) throw new Error('Unable to persist secure storage');
  },
};

// One initializer avoids two mounts generating different identities/storage keys.
let initialized: ReturnType<typeof initialize> | undefined;
async function initialize() {
  const identity = await loadOrCreateIdentity(secureStorage);
  const storage = await createEncryptedStorage(AsyncStorage, secureStorage);
  return { identity, storage };
}
export function loadDevice() {
  initialized ??= initialize().catch((error) => {
    initialized = undefined;
    throw error;
  });
  return initialized;
}
