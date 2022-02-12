### An antivirus program that scans files for a known malicious signature.

###### Build:
```
git clone https://github.com/fib/antivirus.git
cd antivirus
make
```

###### Usage:
```
./antivirus path/to/files path/to/signature
```

* `path/to/files`: path pointing to a directory containing the files to be scanned.
* `path/to/signature`: path to a file containing the malicious signature to look for.

###### Explanation:
This program operates on the principal that some malicious files contain certain byte sequences (also known 
as signatures).
As input, the program accepts a path to a file containing a signature, and a path to a directory containing
files that the user wishes to scan.

After verifying that both of the provided paths are valid, the program will prompt the user to choose one of two
operation modes:

1. **Normal scan**: iterate over the entire file byte-by-byte. Compare every byte sequence of length equal to that
    of the signature to the signature.
3. **Quick scan**: iterate only over the first and last 20% of the file.

Option 1 provides the user with a more thorough scan that will detect any occurrence of the signature,
regardless of its location in the file. Option 2 relies on a hypothetical assumption that such signatures
typically only appear in the beginning or end of a file, and thus allows the user to save a marginal amount
of running time and memory, while possibly sacrificing accuracy.
