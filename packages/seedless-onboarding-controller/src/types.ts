export type OAuthVerifier = 'google' | 'apple';

export type OAuthParams = {
  idToken: string;
  verifier: OAuthVerifier;
  verifierId: string;
};

export type BaseSeedlessMethodsParams = OAuthParams & {
  password: string;
};

export type CreateSeedlessBackupParams = BaseSeedlessMethodsParams & {
  seedPhrase: string;
};

export type RestoreSeedlessBackupParams = BaseSeedlessMethodsParams;
