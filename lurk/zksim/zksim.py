#!/usr/bin/python3
try:
    import shutil as sh
    import subprocess as sp
    import random as rand
    import os
    import prompt_toolkit as pt
except Exception as e:
    print('Check your Python 3 installation.')
    print('Either shutil, subprocess, random, os, or prompt_toolkit is missing.')
    exit(1)
    
class LurkWrapperCmdException(Exception):
    pass

class LurkWrapperCommException(Exception):
    pass

class LurkWrapper:
    def __init__(self, cd, cp):
        lurk_path = sh.which('lurk')
        if lurk_path == None:
            raise LurkWrapperCmdException('Lurk is not installed.')
        self.lurk_cmd = [lurk_path, f'--commits-dir={cd}', f"--proofs-dir={pd}"]

    def _mk_hide_cmd(salt, value):
        assert(salt != None)
        assert(type(value) == list)
        return 'Hide', ['!(hide', f'{salt}'] + value + [')']

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
        hash_idx = out.find('Hash: ') + len('Hash: ')
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
        return out[res_idx:exit_idx]
    
    def _run(self, cmd, cmd_list):
        try:
            echo_p = sp.Popen(["echo"] + cmd_list, stdout=sp.PIPE)
            lurk_p = sp.Popen(self.lurk_cmd, stdin=echo_p.stdout, stdout=sp.PIPE, stderr=sp.PIPE)
            echo_p.stdout.close()
            # Executes echo <cmd> | lurk
            # For example: echo !(hide 123 53) | lurk
            comm_out = lurk_p.communicate(timeout=5)
            if lurk_p.returncode < 0:
                raise LurkWrapperCommException(f'{cmd} failed.')
            else:
                return (comm_out[0]).decode('utf-8') + (comm_out[1]).decode('utf-8')
        except Exception as e:
            print(e)
            raise LurkWrapperCommException('{cmd} failed.')
        
    def hide(self, value):
        salt = rand.randint(10_000_000_000, 100_000_000_000)
        try:
            hide_cmd = LurkWrapper._mk_hide_cmd(salt, value)
            out = self._run(hide_cmd[0], hide_cmd[1])
            if LurkWrapper._has_error(out):
                return 1, LurkWrapper._get_error(out)
            else:
                return 0, LurkWrapper._get_hash(out)
        except:
            raise LurkWrapperCommException('Hide failed.')

    def apply(self, test, value):
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
                return LurkWrapper._get_error(out)
            else:
                # Proof_input is a pair of the hash representing a predicate and
                # the hash representing a value.
                # Proof output is list denoting a (structured) value.
                proof_input, proof_output = LurkWrapper._get_inspect_output(out)
                return test == proof_input[0] and value == proof_input[1] and output in proof_output
        except Exception as e:
            print(e)
            raise LurkWrapperCommException('Inspect failed.')
        
def _load_env(p):
    env = { 'prover' :   {'commits' : [], 'proof_keys' : [] },
            'verifier' : {'commits' : [], 'proof_keys' : [] },
            'public' :   {'commits' : [], 'proof_keys' : [] }}
    return env
        
def _config():
    if (not os.path.exists('./.zksim')):
        print('zksim configuration folder (./.zksim) does not exist. Creating it...')
        try:
            os.makedirs('./.zksim/commits/prover')
            os.makedirs('./.zksim/proofs/prover')
            os.makedirs('./.zksim/commits/verifier')
            os.makedirs('./.zksim/proofs/verifier')
            f = open('.zksim/.zksim_history','w')
            f.close()
        except Exception as e:
            print(e)
            print('Error while creating configuration folders under ./.zksim.')
    else:
        env = _load_env('./.zksim')
    return env, './.zksim/.zksim_history', './.zksim/commits', './.zksim/proofs'

def _handle_hide(zksim_env, party, value, cd, pd):
    assert(party == 'public' or party == 'prover' or party == 'verifier')
    assert(type(value) == list)
    if party != 'public':
        try:
            lurkw = LurkWrapper(f"{cd}/{party}", f"{pd}/{party}")
            rc, secret = lurkw.hide(value)
            if rc > 0:
                print('Hide failed.')
                return None
            if secret not in zksim_env[party]['commits'] and \
               secret not in zksim_env['public']['commits']:
                zksim_env[party]['commits'].append(secret)
            else:
                print('Secret {secret} already created.')
                return None
            value_str = ' '.join(value)
            print(f'Value {value_str} hidden as {secret}.')
        except Exception as e:
            print(e)
            print('Error while executing hide.')
    else:
        print('Public can\'t hide.')
    return secret
    
def _handle_apply(zksim_env, party, test, value, cd, pd):
    assert(party == 'public' or party == 'prover' or party == 'verifier')
    try:
        lurkw = LurkWrapper(f"{cd}/{party}", f"{pd}/{party}")
        out = lurkw.apply(test, value)
        print(out)
    except Exception as e:
        print(e)
        print(f'Error while executing Apply.')

def _handle_prove(zksim_env, party, test, value, cd, pd):
    assert(party == 'public' or party == 'prover' or party == 'verifier')
    if party != 'public':
        try:
            lurkw = LurkWrapper(f"{cd}/{party}", f"{pd}/{party}")
            rc, out = lurkw.prove(test, value)
            key = None
            if rc == 0:
                zksim_env[party]['proof_keys'].append(out)
            key = out
            print(out)
            return key
        except Exception as e:
            print(e)
            print(f'Error while executing Prove.')
    else:
        print('Public can\'t prove.')

def _handle_verify(zksim_env, party, proof_key, cd, pd):
    assert(party == 'public' or party == 'prover' or party == 'verifier')
    try:
        lurkw = LurkWrapper(f"{cd}/{party}", f"{pd}/{party}")
        out = lurkw.verify(proof_key)
        print(out)
    except Exception as e:
        print(e)
        print(f'Error while executing Verify.')

def _handle_inspect(zksim_env, party, proof_key, test, value, output, cd, pd):
    assert(party == 'public' or party == 'prover' or party == 'verifier')
    try:
        lurkw = LurkWrapper(f"{cd}/{party}", f"{pd}/{party}")
        out = lurkw.inspect(proof_key, test, value, output)
        print(out)
    except Exception as e:
        print(e)
        print(f'Error while executing Inspect.')

def _handle_disclose(zksim_env, party, last_secret, last_proof):
    if party != 'public':
        if last_secret != None:
            zksim_env['public']['commits'].append(last_secret)
            print(f'Hash {last_secret} disclosed.')
        elif last_proof != None:
            zksim_env['public']['proof_keys'].append(last_proof)
            print(f'Proof key {last_proof} disclosed.')
        else:
            print('Nothing to disclose.')
    else:
        print('Public can\'t disclose.')
    return None, None

def _handle_disclosed(zksim_env):
    d = zksim_env['public']
    for k in d.keys():
        if d[k] != []:
            print(f'Public {k}: ', end='')
            for h in d[k]:
                print(f'{h} ')

def _handle_env(zksim_env, party):
    for k in zksim_env[party].keys():
        if zksim_env[party][k] != []:
            print(f'{party} {k}: ', end='')
            for e in zksim_env[party][k]:
                print(f'{e} ', end='')
                print()
                
def _main(zksim_env, history_file, commits_dir, proofs_dir):
    cmd = None
    zksim_completer = pt.completion.WordCompleter(
        ['apply', 'call', 'check', 'disclose', 'disclosed', 'env', 'exit', 
         'hide', 'prove', 'prover', 'public', 'verify', 'verifier'], ignore_case=True)
    party = 'prover'
    last_secret = None
    last_proof = None
    cd = commits_dir
    pd = proofs_dir
    session = pt.PromptSession(history=pt.history.FileHistory(history_file))
    while True:
        try:
            cmd = session.prompt('zksim ❯ ', completer=zksim_completer, rprompt=party)
            match cmd.split():
                case ['prover']:
                    party = 'prover'
                case ['verifier']:
                    party = 'verifier'
                case ['public']:
                    party = 'public'
                case ['disclose']:
                    last_secret, last_proof = _handle_disclose(zksim_env, party, last_secret, last_proof)
                case ['disclosed']:
                    _handle_disclosed(zksim_env)
                case ['env']:
                    _handle_env(zksim_env, party)
                case ['hide', *value]:
                    last_secret = _handle_hide(zksim_env, party, value, cd, pd)
                case ['call', test, value]:
                    _handle_apply(zksim_env, party, test, value, cd, pd)
                case ['apply', test, value]:
                    _handle_apply(zksim_env, party, test, value, cd, pd)
                case ['prove', test, value]:
                    last_proof = _handle_prove(zksim_env, party, test, value, cd, pd)
                case ['verify', proof_key]:
                    _handle_verify(zksim_env, party, proof_key, cd, pd)
                case ['check', 'call', test, value, 'reducing', 'to', output, 'in', proof_key]:
                    _handle_inspect(zksim_env, party, proof_key, test, value, output, cd, pd)
                case ['exit']:
                    print('Bye')
                    break
                case other:
                    print(f'Unknown command {other}.')
        except KeyboardInterrupt:
            print()
            continue           
        except EOFError:
            print('\nBye')
            break
    
if __name__ == '__main__':
    try:
        print('Z K  P r o t o c o l Simulator')
        print('Powered by Lurk')
        print()
        env, hf, cd, pd = _config()
        _main(env, hf, cd, pd)
    except Exception as e:
        print(e)
        print(type(e))
        print('zksim internal error.')
        exit(1)
