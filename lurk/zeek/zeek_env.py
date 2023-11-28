try:
    import shutil as sh
    import os
    import string
except Exception as e:
    print(e)
    print('Check your Python 3 installation.')
    print('Either shutil, os or string is missing.')
    exit(1)

class ZeekEnv:
    _COMMITS_DIR = 'commits'
    _PROOFS_DIR  = 'proofs'
    _HASH_SIZE   = 66
    _PROOF_SIZE  = 79
    '''
    A commit or proof is not represented in memory. Any computation that
    requires either one must query the filesystem for it.
    '''
    def __init__(self, dir, timeout=15):
        self._dir     = dir
        self._hist    = f'{dir}/.zeek_history'
        self._party = 'public'
        self.timeout = timeout
        if not os.path.exists(self._dir):
            os.makedirs(self._dir)
        if not os.path.isfile(self._hist):
            f = open(self._hist,'a')
            f.close()
        self._add_party('public')

    def _add_party(self, party):
        assert(os.path.exists(self._dir))
        if (not os.path.exists(f'{self._dir}/{party}')):
            os.makedirs(f'{self._dir}/{party}/{ZeekEnv._COMMITS_DIR}')
            os.makedirs(f'{self._dir}/{party}/{ZeekEnv._PROOFS_DIR}')

    def _get_parties(self):
        assert(os.path.exists(self._dir))
        parties = []
        # os.walk() returns a generator that requires the following
        # repetition.
        for (_, dirnames, _) in os.walk(self._dir):
            parties.extend(dirnames)
            break
        return parties

    def _is_proof(proof):
        proof_prefix = 'Nova_Pallas_10_'
        return (len(proof) == ZeekEnv._PROOF_SIZE) and (proof_prefix in proof) and all(c in string.hexdigits for c in proof.strip(proof_prefix))

    def _is_hash(hash):
        return len(hash) == ZeekEnv._HASH_SIZE and (hash[0:2] == '0x') and all(c in string.hexdigits for c in hash[2:])

    def _set_party(self, party):
        if party in self._get_parties():
           self._party = party
           return True
        else:        
           return False

    def _get_party(self):
        return self._party
    
    def _is_public(self):
        return self._party == 'public'
    
    def _get_hist(self):
        return self._hist
    
    def _get_party_dirs(self):
        return f'{self._dir}/{self._party}/{ZeekEnv._COMMITS_DIR}', \
               f'{self._dir}/{self._party}/{ZeekEnv._PROOFS_DIR }'
    
    def _get_secrets(self, party, secret):
        assert(secret == 'commits' or secret == 'proofs')
        if secret == 'commits':
            dir = f'{self._dir}/{party}/{ZeekEnv._COMMITS_DIR}'
            ext = '.commit'
        else:
            dir = f'{self._dir}/{party}/{ZeekEnv._PROOFS_DIR}'
            ext = '.proof'
        assert(os.path.exists(dir))
        secrets = []
        # os.walk() returns a generator that requires the following
        # repetition.
        for (_, _, filenames) in os.walk(dir):
            secrets.extend(filenames)
            break
        secrets = [ f.split(ext)[0] for f in secrets ]
        if ext == '.proof':
            secrets = [ f for f in secrets if 'meta' not in f ] 
        return secrets

    def _get_commits(self, party):
        return self._get_secrets(party, 'commits')

    def _get_commits_from_party(self):
        return self._get_commits(self._get_party())

    def _get_proofs(self, party):
        return self._get_secrets(party, 'proofs')

    def _get_proofs_from_party(self):
        return self._get_proofs(self._get_party())

    def _is_commit_public(self, hash):
        return self._is_commited('public', hash)

    def _is_commited(self, party, hash):
        return hash in self._get_commits(party)

    def _is_proven(self, party, proof):
        return proof in self._get_proofs(party)

    def _is_commited_by_party(self, hash):
        return self._is_commited(self._get_party(), hash)

    def _is_commited_by_party_or_public(self, hash):
        return self._is_commited(self._get_party(), hash) or self._is_commit_public(hash)
    
    def _disclose_commit(self, party, hash):
        assert(party != 'public')
        assert(self._is_commited(party, hash))
        # shutil.copy2 preserves time.
        sh.copy2(f'{self._dir}/{party}/{ZeekEnv._COMMITS_DIR}/{hash}.commit', 
                 f'{self._dir}/public/{ZeekEnv._COMMITS_DIR}')
        
    def _disclose_commit_from_party(self, hash):
        self._disclose_commit(self._get_party(), hash)

    def _disclose_proof(self, party, proof):
        assert(party != 'public')
        assert(self._is_proven(party, proof))
        # shutil.copy2 preserves time.
        sh.copy2(f'{self._dir}/{party}/{ZeekEnv._PROOFS_DIR}/{proof}.proof', 
                 f'{self._dir}/public/{ZeekEnv._PROOFS_DIR}')
        sh.copy2(f'{self._dir}/{party}/{ZeekEnv._PROOFS_DIR}/{proof}.meta', 
                 f'{self._dir}/public/{ZeekEnv._PROOFS_DIR}')
        
    def _disclose_proof_from_party(self, proof):
        self._disclose_proof(self._get_party(), proof)
