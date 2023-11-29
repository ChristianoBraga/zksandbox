#!/usr/bin/python3
try:
    import os
    import traceback as tb
    from lurk_wrapper import *
    from zeek_env import *
    from zeek_prompt import *
except Exception as e:
    print(e)
    print('Check your Python 3 installation.')
    print('Either os, lurk_wrapper, zeek_env or zeek_prompt is missing.')
    exit(1)
            
def _main(path):
    zeek_prompt = ZeekPrompt(path)
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
                case ['hide', *value, 'in', 'label', label]:
                    zeek_prompt.handle_hide(value)
                case ['hide', *value]:
                    zeek_prompt.handle_hide(value)
                case ['labels']:
                    if not zeek_prompt.empty_labels():
                        [print(f'Secret {s} is labeled {l}') for l, s in zeek_prompt.get_items()]
                    else:
                        print('No labels to print.')
                case ['parties']:
                    zeek_prompt.handle_parties()
                case ['party', 'labeled', label]:
                    if label in zeek_prompt.get_labels():
                        zeek_prompt.handle_party(zeek_prompt.get_value(label))
                    else:
                        print(f'There is no party labeled {label}.')    
                case ['party', hash]:
                    zeek_prompt.handle_party(hash)
                case ['new', 'party', *value, 'labeled', label]:
                    if zeek_prompt.is_public(): 
                        if label not in zeek_prompt.get_labels():
                            out = zeek_prompt.handle_new_party(value)
                            if out != None:
                                zeek_prompt.set_label(label, out) 
                        else:
                            print(f'Label {label} already exists.')
                    else:
                        print('Only public can create party.') 
                case ['new', 'party', *value]:
                    if zeek_prompt.is_public(): 
                        _ = zeek_prompt.handle_new_party(value)
                    else:
                        print('Only public can create party.')                     
                case ['prove', test, value]:
                    last_proof = zeek_prompt.handle_prove(test, value)
                case ['send', 'secret', commit, 'to', target_party]:
                    zeek_prompt.handle_send_commit(target_party, commit)
                case ['send', 'proof', proof_key, 'to', target_party]:
                    zeek_prompt.handle_send_proof(target_party, proof_key)
                case ['verify', proof_key]:
                    zeek_prompt.handle_verify(proof_key)
                case ['run', cmd, 'with', 'labels', *arg_labels]:
                    args = [ zeek_prompt.get_value(l) for l in arg_labels if l in zeek_prompt.get_labels()]
                    if len(args) != len(arg_labels):
                        print('Some of the labels do not exist.')
                        continue
                    zeek_prompt.handle(cmd, args)
                case other:
                    other_str = ' '.join(other)
                    print(f'Unknown command {other_str}.')
        except KeyboardInterrupt:
            print()
            continue           
        except EOFError:
            zeek_prompt.good_bye()
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
        print(tb.print_exc())
        print('zeek internal error.')
        exit(1)
