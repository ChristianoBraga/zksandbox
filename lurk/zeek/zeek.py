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
                case ['call', test_label, value_label]:
                    labels = zeek_prompt.get_labels()
                    if test_label in labels:
                        test  = zeek_prompt.get_value(test_label)
                    elif ZeekEnv.is_hash(test_label):
                        test = test_label
                    else:
                        print(f'Argument {test_label} is neither a label nor a hash.')
                        print('Call failed.')
                        continue
                    if value_label in labels:
                        value = zeek_prompt.get_value(value_label)                        
                    elif ZeekEnv.is_hash(value_label):
                        value = value_label
                    else:
                        print(f'Argument {value_label} is neither a label nor a hash.')
                        print('Call failed.')
                        continue
                    rc, out = zeek_prompt.handle_call(test, value)
                    print(out)
                    if rc == 0:
                        print('Call successful.')
                    else:
                        print('Call failed.')

                case ['check', 'call', test_label, value_label, 'returns',  output_label, 'in', proof_key_label]:
                    labels = zeek_prompt.get_labels()
                    if test_label in labels:
                        test = zeek_prompt.get_value(test_label)
                    elif ZeekEnv.is_hash(test_label):
                        test = test_label
                    else:
                        print(f'Argument {test_label} is neither a label nor a hash.')
                        print('Check failed.')
                        continue
                    if value_label in labels:
                        value = zeek_prompt.get_value(value_label)
                    elif ZeekEnv.is_hash(value_label):
                        value = value_label
                    else:
                        print(f'Argument {value_label} is neither a label nor a hash.')
                        print('Check failed.')
                        continue
                    if output_label in labels:
                        output = zeek_prompt.get_value(output_label)
                    elif output_label != None:
                        output = output_label
                    else:
                        print(f'Argument {output_label} is neither a label nor a value.')
                        print('Check failed.')
                        continue
                    if proof_key_label in labels:
                        proof_key = zeek_prompt.get_value(proof_key_label)
                    elif ZeekEnv.is_proof(proof_key_label):
                        proof_key = proof_key_label
                    else:
                        print(f'Argument {proof_key_label} is neither a label nor a proof key.')
                        print('Check failed.')
                        continue
                    rc, out = zeek_prompt.handle_inspect(proof_key, test, value, output)
                    print(out)
                    if rc == 0:
                        print('Check successful.')
                    else:
                        print('Check failed.')
                case ['env']:
                    commits, proofs = zeek_prompt.handle_env()
                    if commits != []:
                        print('Commits:')
                        [print(f'Secret {c} is labeled {zeek_prompt.find_label_for_value(c)}') 
                            if zeek_prompt.find_label_for_value(c) != None 
                            else print(f'Secret {c} is unlabeled') for c in commits][0]
                    if proofs != []:
                        print('Proofs:')
                        [print(f'Proof {p} is labeled {zeek_prompt.find_label_for_value(p)}') 
                            if zeek_prompt.find_label_for_value(p) != None 
                            else print(f'Proof {p} is unlabeled') for p in proofs][0]
                case ['exit']:
                    zeek_prompt.good_bye()
                    break
                case ['help']:
                    print('To be written...')
                case ['hide', *value, 'in', label]:
                    if label in zeek_prompt.get_labels():
                       print(f'Label {label} exists.')
                       print('Hide failed.')
                       continue
                    else:
                       rc, out = zeek_prompt.handle_hide(value)
                       print(out)
                       if rc == 0:
                          zeek_prompt.set_label(label, out)
                          print('Hide successful.')
                       else:
                          print('Hide failed.')
                case ['hide', *value]:
                    rc, out = zeek_prompt.handle_hide(value)
                    print(out)
                    if rc == 0:
                       print('Hide successful.')
                    else:
                       print('Hide failed.')
                case ['labels']:
                    if not zeek_prompt.empty_labels():
                        [print(f'Secret {s} is labeled {l}') for l, s in zeek_prompt.get_items()]
                    else:
                        print('No labels to print.')
                case ['parties']:
                    rc, out = zeek_prompt.handle_parties()
                    if rc == 0:
                        [print(f'Party {p} is labeled {zeek_prompt.find_label_for_value(p)}') 
                            if zeek_prompt.find_label_for_value(p) != None 
                            else print(p) if p == 'public' 
                                          else print(f'Party {p} is unlabeled') for p in out][0]
                    else:
                        print(out)
                        print('Parties failed.')
                case ['party', label]:
                    if label in zeek_prompt.get_labels():
                       party = zeek_prompt.get_value(label)
                    else:
                       party = label
                    rc, out = zeek_prompt.handle_party(party)
                    print(out)
                    if rc == 0:
                       print('Party successful.')
                    else:
                       print('Party failed.')
                case ['new', 'party', *value]:
                    if zeek_prompt.is_public(): 
                        rc, out = zeek_prompt.handle_new_party(value)
                        print(out)
                        if rc == 0:
                           print('New party successful.')
                        else:
                           print('New party failed.')
                    else:
                        print('Only public can create party.')                     
                case ['new', 'party', *value, 'labeled', label]:
                    if zeek_prompt.is_public(): 
                        if label not in zeek_prompt.get_labels():
                            rc, out = zeek_prompt.handle_new_party(value)
                            print(out)
                            if rc == 0:
                                zeek_prompt.set_label(label, out)
                                print('New party successful.')
                            else:
                                print('New party failed.')
                        else:
                            print(f'Label {label} already exists.')
                    else:
                        print('Only public can create a party.') 
                case ['prove', test_label, value_label, 
                      'in',    proof_key_label]:
                    if not zeek_prompt.is_public():
                        if test_label in zeek_prompt.get_labels() and \
                           value_label in zeek_prompt.get_labels():
                           test = zeek_prompt.get_value(test_label)
                           value = zeek_prompt.get_value(value_label) 
                           rc, proof_key = zeek_prompt.handle_prove(test, value)
                           print(proof_key)
                           if rc == 0:
                              zeek_prompt.set_label(proof_key_label, proof_key)
                              print(f'Prove sucessful.')
                           else:
                              print(f'Prove failed.')
                        else:
                           print('Labels do not exist.')
                    else:
                       print(f'Change party to the one holding secrets {test_label} and {value_label}.')
                case ['prove', test, value]:
                    if not zeek_prompt.is_public():
                      if ZeekEnv.is_hash(test) and ZeekEnv.is_hash(value):
                          rc, out = zeek_prompt.handle_prove(test, value)
                          print(out)
                          if rc == 0:
                             print(f'Prove sucessful.')
                          else:
                             print(f'Prove failed.')
                      else:
                          print('Both arguments of prove should be hashes.') 
                    else:
                       print(f'Change party to the one holding secrets {test_label} and {value_label}.')
                case ['send', 'secret', commit, 'to', target_party]:
                    if not zeek_prompt.is_public():
                        labels = zeek_prompt.get_labels()
                        if target_party in labels:
                            party = zeek_prompt.get_value(target_party)
                        elif ZeekEnv.is_hash(target_party):
                            party = target_party
                        else:
                            print(f'Argument {target_party} is neither a label nor a hash.')
                            continue
                        if party == zeek_prompt.get_party():
                            print(f'Can not send secret to oneself.\nParty {target_party} is the current party.')
                            continue
                        if commit in labels:
                            value = zeek_prompt.get_value(commit)
                        elif ZeekEnv.is_hash(commit):
                            value = commit
                        else:
                            print(f'Argument {commit} is neither a label nor a hash.')
                            continue
                        rc, out = zeek_prompt.handle_send_commit(party, value)
                        print(out)
                        if rc == 0:
                           print(f'Send secret sucessful.')
                        else:
                           print(f'Send secret failed.')
                    else:
                        print(f'Change party to the one holding secret {commit}.')
                case ['send', 'proof', proof_key, 'to', target_party]:
                    if not zeek_prompt.is_public():
                        labels = zeek_prompt.get_labels()
                        if target_party in labels:
                            party = zeek_prompt.get_value(target_party)
                        elif ZeekEnv.is_hash(target_party):
                            party = target_party
                        else:
                            print(f'Argument {target_party} is neither a label nor a hash.')
                            continue
                        if party == zeek_prompt.get_party():
                            print(f'Can not send proof to oneself.\nParty {target_party} the is current party.')
                            continue
                        if proof_key in labels:
                            proof = zeek_prompt.get_value(proof_key)
                        elif ZeekEnv.is_proof(proof_key):
                            proof = proof_key
                        else:
                            print(f'Argument {proof_key} is neither a label nor a proof key.')
                            continue
                        rc, out = zeek_prompt.handle_send_proof(party, proof)
                        print(out)
                        if rc == 0:
                           print(f'Send proof sucessful.')
                        else:
                           print(f'Send proof failed.')
                    else:
                        print(f'Change party to the one holding proof {proof_key}.')
                case ['verify', proof_key]:
                    if ZeekEnv.is_proof(proof_key):
                        value = proof_key
                    elif proof_key in zeek_prompt.get_labels():
                        value = zeek_prompt.get_value(proof_key)
                        rc, out = zeek_prompt.handle_verify(f'\"{value}\"')
                        out = out.replace('"', '')
                        print(out)
                        if rc == 0:
                           print(f'Verify proof sucessful.')
                        else:
                           print(f'Verify proof failed.')    
                    else:
                        print(f'Argument {proof_key} is neither a label or a proof key.')                  
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
