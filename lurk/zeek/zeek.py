#!/usr/bin/python3
try:
    import shutil as sh
    import subprocess as sp
    import random as rand
    import os
    import prompt_toolkit as pt
    import string
    from lurk_wrapper import *
except Exception as e:
    print(e)
    print('Check your Python 3 installation.')
    print('Either shutil, subprocess, random, os, prompt_toolkit, string or lurkwrapper is missing.')
    exit(1)
            
def _handle_call(zeek_env, test, value):
    assert(type(value) != list)
    try:
        cd, pd = zeek_env._get_party_dirs()
        lurkw = LurkWrapper(zeek_env.timeout, cd, pd)
        out = lurkw.call('0x'+test, '0x'+value)
        print(out)
    except Exception as e:
        print(e)
        print(f'Unexpected error while executing Call.')

def _handle_hide(zeek_env, value):
    assert(type(value) == list)
    if not zeek_env._is_public():
        try:
            cd, pd = zeek_env._get_party_dirs()
            lurkw = LurkWrapper(zeek_env.timeout, cd, pd)
            rc, out = lurkw.hide(value)
            if rc > 0:
                print(out)
                print('Hide failed.')
                return None
            else:
                value_str = ' '.join(value)
                print(f'Value {value_str} hidden as {out}')
                return out
        except Exception as e:
            print(e)
            print('Unexpected error while executing hide.')
    else:
        print('Public can\'t hide.')
        return None

def _handle_parties(zeek_env):
    parties = zeek_env._get_parties()
    if parties != []:
        print('Parties:')
        parties.sort()
        [print(p) for p in parties]

def _handle_party(zeek_env, hash):
    current_party = zeek_env._get_party()  
    if hash == current_party:
        print(f'Party is already {current_party}.')
    else: 
        if zeek_env._set_party(hash):
           print(f'Party set to {hash}.')
        else:
           print(f'Party {hash} does not exist.\nParty is still {zeek_env._get_party()}.')
           print('Party failed.')


def _handle_new_party(zeek_env, value):
    assert(type(value) == list)
    if zeek_env._is_public():
        try:
            cd, pd = zeek_env._get_party_dirs()
            lurkw = LurkWrapper(zeek_env.timeout, cd, pd)
            rc, out = lurkw.hide(value)
            if rc > 0:
                print(out)
                print('New party failed.')
            else:
                zeek_env._add_party(out)            
                value_str = ' '.join(value)    
                print(f'Party {out} created for {value_str}.')
        except Exception as e:
            print(e)
            print('Unexpected error while executing New party.')
    else:
        print('Only Public can Party.')

def _handle_prove(zeek_env, test, value):
    if not zeek_env._is_public():
        try:
            cd, pd = zeek_env._get_party_dirs()
            lurkw = LurkWrapper(zeek_env.timeout, cd, pd)
            rc, out = lurkw.prove('0x'+test, '0x'+value)
            key = None
            if rc > 0:
                print(out)
                print('Prove failed.')
            else:
                key = out
                print(f'Proof key {out} generated for call {test} {value}')
            return key
        except Exception as e:
            print(e)
            print(f'Unexpected error while executing Prove.')
    else:
        print('Public can\'t prove.')

def _handle_verify(zeek_env, proof_key):
    try:
        cd, pd = zeek_env._get_party_dirs()
        lurkw = LurkWrapper(zeek_env.timeout, cd, pd)
        out = lurkw.verify(proof_key)
        print(out)
    except Exception as e:
        print(e)
        print(f'Unexpected error while executing Verify.')

def _handle_inspect(zeek_env, proof_key, test, value, output):
    try:
        cd, pd = zeek_env._get_party_dirs()
        lurkw = LurkWrapper(zeek_env.timeout, cd, pd)
        rc, out = lurkw.inspect('\"'+proof_key+'\"', '0x'+test, '0x'+value, output)       
        print(out)
        if rc > 0:
            print('Inspect failed.')
    except Exception as e:
        print(e)
        print(f'Unexpected error while executing Inspect.')

def _handle_disclose_proof(zeek_env, proof):
    if not zeek_env._is_public():
        if proof != None:
            if ZeekEnv._is_proof(proof):
                zeek_env._disclose_proof_from_party(proof)
                print(f'Proof {proof} disclosed.')
            else:
                print(f'Proof {proof} in wrong format.')
        else:
            print(f'Can\'t disclose {proof}.')
    else:       
        print('Public can\'t disclose.')

def _handle_disclose_hash(zeek_env, hash):
    if not zeek_env._is_public():
        if hash != None:
            zeek_env._disclose_commit_from_party(hash)
            print(f'Hash {hash} disclosed.')
        else:
            print(f'Can\'t disclose {hash}.')
    else:
        print('Public can\'t disclose.')

def _handle_disclose(zeek_env, last_secret, last_proof):
    if not zeek_env._is_public():
        if last_secret != None:
            zeek_env._disclose_commit_from_party(last_secret)
            print(f'Hash {last_secret} disclosed.')
        elif last_proof != None:
            zeek_env._disclose_proof_from_party(last_proof)
            print(f'Proof key {last_proof} disclosed.')
        else:
            print('Nothing to disclose.')
    else:
        print('Public can\'t disclose.')
    return None, None

def _handle_disclosed(zeek_env):
    print(f'Commits from public:')
    for c in zeek_env._get_commits('public'):
        print(c)
    print(f'Proofs from public:')
    for p in zeek_env._get_proofs('public'):
        print(p)

def _handle_env(zeek_env):
    party = zeek_env._get_party()
    commits = zeek_env._get_commits_from_party()
    if commits != []:
        print(f'Commits from {party}:')
        for c in commits:
            print(f'\t{c}')
    proofs = zeek_env._get_proofs_from_party()
    if proofs != []:
        print(f'Proofs from {party}:')
        for p in proofs:
            print(f'\t{p}')

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

class ZeekPrompt:
    def __init__(self, hist):
        self.completer = pt.completion.WordCompleter(
            ['call', 'check', 'disclose', 'disclosed', 'env', 'exit', 'help',
             'hide', 'party', 'prove', 'public', 'verify'], ignore_case=True)
        self.session = pt.PromptSession(history=pt.history.FileHistory(hist))

    def prompt(self, party):
        return self.session.prompt('zeek ❯ ', completer=self.completer, rprompt=party)
    
def _main(path):
    zeek_env    = ZeekEnv(path)
    zeek_prompt = ZeekPrompt(zeek_env._get_hist())
    last_secret  = None
    last_proof   = None
    cmd          = None
    while True:
        try:
            cmd = zeek_prompt.prompt(zeek_env._get_party())
            match cmd.split():
                case ['call', test, value]:
                    _handle_call(zeek_env, test, value)
                case ['check', 'call', test, value, 'returns',  output, 'in', proof_key]:
                    _handle_inspect(zeek_env, proof_key, test, value, output)
                case ['disclose']:
                    last_secret, last_proof = _handle_disclose(zeek_env, last_secret, last_proof)
                case ['disclose', 'hash', hash]:
                    _handle_disclose_hash(zeek_env, hash)
                case ['disclose', 'proof', proof]:
                    _handle_disclose_proof(zeek_env, proof)
                case ['disclosed']:
                    _handle_disclosed(zeek_env)
                case ['env']:
                    _handle_env(zeek_env)
                case ['exit']:
                    print('Bye')
                    break
                case ['help']:
                    print('To be written...')
                case ['hide', *value]:
                    last_secret = _handle_hide(zeek_env, value)
                case ['parties']:
                    _handle_parties(zeek_env)
                case ['party', hash]:
                    _handle_party(zeek_env, hash)
                case ['new', 'party', *value]:
                    _handle_new_party(zeek_env, value)
                case ['prove', test, value]:
                    last_proof = _handle_prove(zeek_env, test, value)
                case ['public']:
                    party = 'public'
                case ['verify', proof_key]:
                    _handle_verify(zeek_env, proof_key)
                case other:
                    other_str = ' '.join(other)
                    print(f'Unknown command {other_str}.')
        except KeyboardInterrupt:
            print()
            continue           
        except EOFError:
            print('\nBye')
            break

if __name__ == '__main__':
    try:
        os.system('clear')
        print('Zeek: ZK Protocol Simulator')
        print('Powered by Lurk')
        print()
        _main(f'{os.getcwd()}/.zeek')
    except Exception as e:
        print(e)
        print(type(e))
        print('zeek internal error.')
        exit(1)
