#!/usr/bin/python3
try:
    import shutil as sh
    import subprocess as sp
    import random as rand
    import os
    import prompt_toolkit as pt
    import string
except Exception as e:
    print(e)
    print('Check your Python 3 installation.')
    print('Either shutil, subprocess, random, os, prompt_toolkit or string is missing.')
    exit(1)
    
class LurkWrapperCmdException(Exception):
    pass

class LurkWrapperCommException(Exception):
    pass

class LurkWrapper:
    def __init__(self, timeout, cd, pd):
        lurk_path = sh.which('lurk')
        if lurk_path == None:
            raise LurkWrapperCmdException('Lurk is not installed.')
        self._timeout = timeout
        self._lurk_cmd = [lurk_path, f'--commits-dir={cd}', f"--proofs-dir={pd}"]

    def _mk_hide_cmd(salt, value):
        '''
        For the moment, only numbers, strings and code are allowed.
        '''
        assert(salt != None)
        assert(type(value) == list)
        if len(value) == 1 and value[0].isalpha():
            value = ['\"' + value[0] + '\"']
        cmd = 'Hide', ['!(hide', f'{salt}'] + value + [')']
        return cmd

    def _mk_apply_cmd(test, value):
        assert(test != None)
        assert(value != None)
        return 'Apply', ['!(fetch', f'{test})\n', '!(fetch', f'{value})\n', '((open', f'{test})', '(open', f'{value}))']

    def _mk_prove_cmd(test, value):
        apply_cmd = LurkWrapper._mk_apply_cmd(test, value)
        return 'Prove', apply_cmd[1] + ['\n!(prove)']

    def _mk_verify_cmd(proof_key):
        assert(proof_key != '' and proof_key != None)
        return 'Verify', ['!(verify', f'{proof_key})']

    def _mk_inspect_cmd(proof_key):
        assert(proof_key != '' and proof_key != None)
        return 'Verify', ['!(inspect', f'{proof_key})']
    
    def _has_error(out):
        assert(out != '' or out != None)
        return out.find('Error:') > 0

    def _get_error(out):
        assert(out != '' or out != None)
        return out[out.find('Error:'):len(out)-1]
    
    def _get_hash(out):
        assert(not LurkWrapper._has_error(out))
        hash_idx = out.find('Hash: 0x') + len('Hash: 0x')
        exit_idx = out.find('\nExiting...')
        return out[hash_idx:exit_idx]

    def _get_output(out):
        assert(not LurkWrapper._has_error(out))
        res_idx = out.find('=> ')
        res_idx += len('=> ')
        exit_idx = out.find('\nExiting...')
        return out[res_idx:exit_idx]

    def _get_verify_output(out):
        assert(not LurkWrapper._has_error(out))
        res_idx = out.find('Proof ')
        exit_idx = out.find('\nExiting...')
        return out[res_idx:exit_idx]

    def _get_inspect_output(out):
        assert(not LurkWrapper._has_error(out))
        out_list = out.split()
        input_idx  = out_list.index('Input:')
        output_idx = out_list.index('Output:')
        iterations_idx = out_list.index('Iterations:')
        # It's assumed that the input is of the form
        # ((open <hash 1>)(open <hash 2>))
        # Therefore, <hash 1> is located at index 1 and <hash 2> is located at index 3.
        input_list = out_list[input_idx + 1:output_idx]
        input_hashes = input_list[1].strip(')'), input_list[3].strip(')')
        # Output value is a list
        output_value = out_list[output_idx + 1:iterations_idx] 
        return input_hashes, output_value
    
    def _get_proof_key(out):
        assert(not LurkWrapper._has_error(out))
        # Proof keys are surrouded by "" so we need to adjust the indices
        res_idx = out.find('Proof key: ') + len('Proof key: ') + 1 
        exit_idx = out.find('\nExiting...') - 1 
        return out[res_idx:exit_idx].strip('\"')
    
    def _run(self, cmd, cmd_list):
        try:
            echo_p = sp.Popen(["echo"] + cmd_list, stdout=sp.PIPE)
            lurk_p = sp.Popen(self._lurk_cmd, stdin=echo_p.stdout, stdout=sp.PIPE, stderr=sp.PIPE)
            echo_p.stdout.close()
            # Executes echo <cmd> | lurk
            # For example: echo !(hide 123 53) | lurk
            comm_out = lurk_p.communicate(timeout=self._timeout)
            if lurk_p.returncode < 0:
                raise LurkWrapperCommException(f'{cmd} failed.')
            else:
                return (comm_out[0]).decode('utf-8') + (comm_out[1]).decode('utf-8')
        except Exception as e:
            print(e)
            raise LurkWrapperCommException(f'{cmd} failed.')
        
    def hide(self, value):
        salt = rand.randint(10_000_000_000, 100_000_000_000)
        try:
            hide_cmd = LurkWrapper._mk_hide_cmd(salt, value)
            out = self._run(hide_cmd[0], hide_cmd[1])
            if LurkWrapper._has_error(out):
                return 1, LurkWrapper._get_error(out)
            else:
                return 0, LurkWrapper._get_hash(out)
        except Exception as e:
            print(e)
            raise LurkWrapperCommException('Hide failed.')

    def call(self, test, value):
        try:
            apply_cmd = LurkWrapper._mk_apply_cmd(test, value)
            out = self._run(apply_cmd[0], apply_cmd[1])
            if LurkWrapper._has_error(out):
                return LurkWrapper._get_error(out)
            else:
                return LurkWrapper._get_output(out)
        except Exception as e:
            print(e)
            raise LurkWrapperCommException('Apply failed.')

    def prove(self, test, value):
        try:
            prove_cmd = LurkWrapper._mk_prove_cmd(test, value)
            out = self._run(prove_cmd[0], prove_cmd[1])
            if LurkWrapper._has_error(out):
                return 1, LurkWrapper._get_error(out)
            else:
                return 0, LurkWrapper._get_proof_key(out)
        except Exception as e:
            print(e)
            raise LurkWrapperCommException('Prove failed.')

    def verify(self, proof_key):
        try:
            verify_cmd = LurkWrapper._mk_verify_cmd(proof_key)
            out = self._run(verify_cmd[0], verify_cmd[1])
            if LurkWrapper._has_error(out):
                return LurkWrapper._get_error(out)
            else:
                return LurkWrapper._get_verify_output(out)
        except Exception as e:
            print(e)
            raise LurkWrapperCommException('Verify failed.')

    def inspect(self, proof_key, test, value, output):
        try:
            inspect_cmd = LurkWrapper._mk_inspect_cmd(proof_key)
            out = self._run(inspect_cmd[0], inspect_cmd[1])
            if LurkWrapper._has_error(out):
                return 1, LurkWrapper._get_error(out)
            else:
                # Proof_input is a pair of the hash representing a predicate and
                # the hash representing a value.
                # Proof output is list denoting a (structured) value.
                proof_input, proof_output = LurkWrapper._get_inspect_output(out)
                return 0, (test == proof_input[0] and value == proof_input[1] and output in proof_output)
        except Exception as e:
            print(e)
            raise LurkWrapperCommException('Inspect failed.')
        
def _handle_call(zksim_env, test, value):
    assert(type(value) != list)
    try:
        cd, pd = zksim_env._get_party_dirs()
        lurkw = LurkWrapper(zksim_env.timeout, cd, pd)
        out = lurkw.call('0x'+test, '0x'+value)
        print(out)
    except Exception as e:
        print(e)
        print(f'Unexpected error while executing Call.')

def _handle_hide(zksim_env, value):
    assert(type(value) == list)
    if not zksim_env._is_public():
        try:
            cd, pd = zksim_env._get_party_dirs()
            lurkw = LurkWrapper(zksim_env.timeout, cd, pd)
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

def _handle_parties(zksim_env):
    parties = zksim_env._get_parties()
    if parties != []:
        print('Parties:')
        parties.sort()
        [print(p) for p in parties]

def _handle_party(zksim_env, hash):
    current_party = zksim_env._get_party()  
    if hash == current_party:
        print(f'Party is already {current_party}.')
    else: 
        if zksim_env._set_party(hash):
           print(f'Party set to {hash}.')
        else:
           print(f'Party {hash} does not exist.\nParty is still {zksim_env._get_party()}.')
           print('Party failed.')


def _handle_new_party(zksim_env, value):
    assert(type(value) == list)
    if zksim_env._is_public():
        try:
            cd, pd = zksim_env._get_party_dirs()
            lurkw = LurkWrapper(zksim_env.timeout, cd, pd)
            rc, out = lurkw.hide(value)
            if rc > 0:
                print(out)
                print('New party failed.')
            else:
                zksim_env._add_party(out)            
                value_str = ' '.join(value)    
                print(f'Party {out} created for {value_str}.')
        except Exception as e:
            print(e)
            print('Unexpected error while executing New party.')
    else:
        print('Only Public can Party.')

def _handle_prove(zksim_env, test, value):
    if not zksim_env._is_public():
        try:
            cd, pd = zksim_env._get_party_dirs()
            lurkw = LurkWrapper(zksim_env.timeout, cd, pd)
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

def _handle_verify(zksim_env, proof_key):
    try:
        cd, pd = zksim_env._get_party_dirs()
        lurkw = LurkWrapper(zksim_env.timeout, cd, pd)
        out = lurkw.verify(proof_key)
        print(out)
    except Exception as e:
        print(e)
        print(f'Unexpected error while executing Verify.')

def _handle_inspect(zksim_env, proof_key, test, value, output):
    try:
        cd, pd = zksim_env._get_party_dirs()
        lurkw = LurkWrapper(zksim_env.timeout, cd, pd)
        rc, out = lurkw.inspect('\"'+proof_key+'\"', '0x'+test, '0x'+value, output)       
        print(out)
        if rc > 0:
            print('Inspect failed.')
    except Exception as e:
        print(e)
        print(f'Unexpected error while executing Inspect.')

def _handle_disclose_proof(zksim_env, proof):
    if not zksim_env._is_public():
        if proof != None:
            if ZKSimEnv._is_proof(proof):
                zksim_env._disclose_proof_from_party(proof)
                print(f'Proof {proof} disclosed.')
            else:
                print(f'Proof {proof} in wrong format.')
        else:
            print(f'Can\'t disclose {proof}.')
    else:       
        print('Public can\'t disclose.')

def _handle_disclose_hash(zksim_env, hash):
    if not zksim_env._is_public():
        if hash != None:
            zksim_env._disclose_commit_from_party(hash)
            print(f'Hash {hash} disclosed.')
        else:
            print(f'Can\'t disclose {hash}.')
    else:
        print('Public can\'t disclose.')

def _handle_disclose(zksim_env, last_secret, last_proof):
    if not zksim_env._is_public():
        if last_secret != None:
            zksim_env._disclose_commit_from_party(last_secret)
            print(f'Hash {last_secret} disclosed.')
        elif last_proof != None:
            zksim_env._disclose_proof_from_party(last_proof)
            print(f'Proof key {last_proof} disclosed.')
        else:
            print('Nothing to disclose.')
    else:
        print('Public can\'t disclose.')
    return None, None

def _handle_disclosed(zksim_env):
    print(f'Commits from public:')
    for c in zksim_env._get_commits('public'):
        print(c)
    print(f'Proofs from public:')
    for p in zksim_env._get_proofs('public'):
        print(p)

def _handle_env(zksim_env):
    party = zksim_env._get_party()
    commits = zksim_env._get_commits_from_party()
    if commits != []:
        print(f'Commits from {party}:')
        for c in commits:
            print(f'\t{c}')
    proofs = zksim_env._get_proofs_from_party()
    if proofs != []:
        print(f'Proofs from {party}:')
        for p in proofs:
            print(f'\t{p}')

class ZKSimEnv:
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
        self._hist    = f'{dir}/.zksim_history'
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
            os.makedirs(f'{self._dir}/{party}/{ZKSimEnv._COMMITS_DIR}')
            os.makedirs(f'{self._dir}/{party}/{ZKSimEnv._PROOFS_DIR}')

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
        return (len(proof) == ZKSimEnv._PROOF_SIZE) and (proof_prefix in proof) and all(c in string.hexdigits for c in proof.strip(proof_prefix))

    def _is_hash(hash):
        return len(hash) == ZKSimEnv._HASH_SIZE and (hash[0:2] == '0x') and all(c in string.hexdigits for c in hash[2:])

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
        return f'{self._dir}/{self._party}/{ZKSimEnv._COMMITS_DIR}', \
               f'{self._dir}/{self._party}/{ZKSimEnv._PROOFS_DIR }'
    
    def _get_secrets(self, party, secret):
        assert(secret == 'commits' or secret == 'proofs')
        if secret == 'commits':
            dir = f'{self._dir}/{party}/{ZKSimEnv._COMMITS_DIR}'
            ext = '.commit'
        else:
            dir = f'{self._dir}/{party}/{ZKSimEnv._PROOFS_DIR}'
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
        sh.copy2(f'{self._dir}/{party}/{ZKSimEnv._COMMITS_DIR}/{hash}.commit', 
                 f'{self._dir}/public/{ZKSimEnv._COMMITS_DIR}')
        
    def _disclose_commit_from_party(self, hash):
        self._disclose_commit(self._get_party(), hash)

    def _disclose_proof(self, party, proof):
        assert(party != 'public')
        assert(self._is_proven(party, proof))
        # shutil.copy2 preserves time.
        sh.copy2(f'{self._dir}/{party}/{ZKSimEnv._PROOFS_DIR}/{proof}.proof', 
                 f'{self._dir}/public/{ZKSimEnv._PROOFS_DIR}')
        sh.copy2(f'{self._dir}/{party}/{ZKSimEnv._PROOFS_DIR}/{proof}.meta', 
                 f'{self._dir}/public/{ZKSimEnv._PROOFS_DIR}')
        
    def _disclose_proof_from_party(self, proof):
        self._disclose_proof(self._get_party(), proof)

class ZKSimPrompt:
    def __init__(self, hist):
        self.completer = pt.completion.WordCompleter(
            ['call', 'check', 'disclose', 'disclosed', 'env', 'exit', 'help',
             'hide', 'party', 'prove', 'public', 'verify'], ignore_case=True)
        self.session = pt.PromptSession(history=pt.history.FileHistory(hist))

    def prompt(self, party):
        return self.session.prompt('zksim ❯ ', completer=self.completer, rprompt=party)
    
def _main(path):
    zksim_env    = ZKSimEnv(path)
    zksim_prompt = ZKSimPrompt(zksim_env._get_hist())
    last_secret  = None
    last_proof   = None
    cmd          = None
    while True:
        try:
            cmd = zksim_prompt.prompt(zksim_env._get_party())
            match cmd.split():
                case ['call', test, value]:
                    _handle_call(zksim_env, test, value)
                case ['check', 'call', test, value, 'returns',  output, 'in', proof_key]:
                    _handle_inspect(zksim_env, proof_key, test, value, output)
                case ['disclose']:
                    last_secret, last_proof = _handle_disclose(zksim_env, last_secret, last_proof)
                case ['disclose', 'hash', hash]:
                    _handle_disclose_hash(zksim_env, hash)
                case ['disclose', 'proof', proof]:
                    _handle_disclose_proof(zksim_env, proof)
                case ['disclosed']:
                    _handle_disclosed(zksim_env)
                case ['env']:
                    _handle_env(zksim_env)
                case ['exit']:
                    print('Bye')
                    break
                case ['help']:
                    print('To be written...')
                case ['hide', *value]:
                    last_secret = _handle_hide(zksim_env, value)
                case ['parties']:
                    _handle_parties(zksim_env)
                case ['party', hash]:
                    _handle_party(zksim_env, hash)
                case ['new', 'party', *value]:
                    _handle_new_party(zksim_env, value)
                case ['prove', test, value]:
                    last_proof = _handle_prove(zksim_env, test, value)
                case ['public']:
                    party = 'public'
                case ['verify', proof_key]:
                    _handle_verify(zksim_env, proof_key)
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
        print('Z K  P r o t o c o l Simulator')
        print('Powered by Lurk')
        print()
        _main(f'{os.getcwd()}/.zksim')
    except Exception as e:
        print(e)
        print(type(e))
        print('zksim internal error.')
        exit(1)
