#!/usr/bin/python3
try:
    import os
    import prompt_toolkit as pt
    from lurk_wrapper import *
    from zeek_env import *
    from zeek_prompt import *
except Exception as e:
    print(e)
    print('Check your Python 3 installation.')
    print('Either shutil, subprocess, random, os, prompt_toolkit, string or lurk_wrapper is missing.')
    exit(1)
            
def _main(path):
    zeek_prompt = ZeekPrompt(ZeekEnv(path))
    last_secret = None
    last_proof  = None
    cmd         = None
    while True:
        try:
            cmd = zeek_prompt.prompt()
            match cmd.split():
                case ['call', test, value]:
                    zeek_prompt.handle_call(test, value)
                case ['check', 'call', test, value, 'returns',  output, 'in', proof_key]:
                    zeek_prompt.handle_inspect(proof_key, test, value, output)
                case ['env']:
                    zeek_prompt.handle_env()
                case ['exit']:
                    print('Bye')
                    break
                case ['help']:
                    print('To be written...')
                case ['hide', *value]:
                    last_secret = zeek_prompt.handle_hide(value)
                case ['parties']:
                    zeek_prompt.handle_parties()
                case ['party', hash]:
                    zeek_prompt.handle_party(hash)
                case ['new', 'party', *value]:
                    zeek_prompt.handle_new_party(value)
                case ['prove', test, value]:
                    last_proof = zeek_prompt.handle_prove(test, value)
                case ['send', 'secret', commit, 'to', target_party]:
                    zeek_prompt.handle_send_commit(target_party, commit)
                case ['send', 'proof', proof_key, 'to', target_party]:
                    zeek_prompt.handle_send_proof(target_party, proof_key)
                case ['verify', proof_key]:
                    zeek_prompt.handle_verify(proof_key)
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
        print('Zeek: Prototype ZK Protocol Simulator')
        print('Powered by Lurk')
        print()
        _main(f'{os.getcwd()}/.zeek')
    except Exception as e:
        print(e)
        print(type(e))
        print('zeek internal error.')
        exit(1)
