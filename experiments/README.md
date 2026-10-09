## Attacker Models

How to recreate the attacks showcased in the paper:

## A1

Benign:
```
python3 adversary.py listen ../user_configs/bob.yaml 1
```

Malicious:
```
python3 adversary.py query ../user_configs/mallory.yaml .. user_configs/bob.yaml 1
```

## A2

Benign:
```
python3 adversary.py listen ../user_configs/bob.yaml 2
```

Malicious:
```
python3 adversary.py query ../user_configs/mallory.yaml .. user_configs/bob.yaml 2
```

## A3

Benign:
```
python3 adversary.py listen ../user_configs/bob.yaml 3
```

Malicious:
```
python3 adversary.py query ../user_configs/mallory.yaml .. user_configs/bob.yaml 3
```

## A4

Benign:
```
python3 adversary.py listen ../user_configs/bob.yaml 4
```

Malicious:
```
python3 adversary.py query ../user_configs/mallory.yaml .. user_configs/bob.yaml 4
```

## A5

Benign:
```
python3 adversary.py listen ../user_configs/bob.yaml None 5
```

Malicious:
```
python3 adversary.py query ../user_configs/alice.yaml ../user_configs/bob.yaml 5 ../user_configs/mallory.yaml
```

## A6

Benign:
```
python3 adversary.py listen ../user_configs/candice.yaml 6
```

Malicious:
```
python3 adversary.py query ../user_configs/mallory.yaml .. user_configs/candice.yaml 6
```

## A7

By the assumptions of the design of the system, such an attack will be prevented from the Human Verification service deployed from the Provider.

## A8

Benign:
```
python3 adversary.py listen ../user_configs/bob.yaml 8
```

Malicious:
```
python3 adversary.py query ../user_configs/mallory.yaml .. user_configs/bob.yaml 8
```