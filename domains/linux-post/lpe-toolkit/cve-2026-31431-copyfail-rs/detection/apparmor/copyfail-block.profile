# AppArmor profile fragment — block AF_ALG for unprivileged processes
#
# Install: cp this file to /etc/apparmor.d/copyfail-block, then
#   apparmor_parser -r /etc/apparmor.d/copyfail-block
#   aa-enforce copyfail-block
#
# Compile-test before deploy:
#   apparmor_parser -p copyfail-block.profile
#
# Requires AppArmor 3.0+ (network alg rule).

abi <abi/3.0>,

profile copyfail-block flags=(attach_disconnected) {
    capability,
    audit deny network alg,     # log + block AF_ALG creation (the CopyFail trigger)
    network,                    # everything else allowed

    file,
    /** rwklix,
}

# Note: this is a minimal profile. For production, attach the rule to
# specific binaries (su, sudo, passwd) instead of a global profile.
# Example: edit /etc/apparmor.d/usr.bin.passwd to add `audit deny network alg,`.
