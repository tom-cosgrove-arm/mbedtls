#!/usr/bin/env perl
#
use strict;
use Data::Dumper;

# Globals (sorry!)
my %functions = get_functions();
my @functions = sort keys %functions;

write_function_codes("psa_functions_codes.h");

write_client_calls("psa_sim_crypto_client.c");

write_server_implementations("psa_sim_crypto_server.c");

sub write_function_codes
{
    my ($file) = @_;

    open(my $fh, ">", $file) || die("$0: $file: $!\n");

    # NOTE: psa_crypto_init() is written manually

    print $fh <<EOF;
/* THIS FILE WAS AUTO-GENERATED BY $0. DO NOT EDIT!! */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef _PSA_FUNCTIONS_CODES_H_
#define  _PSA_FUNCTIONS_CODES_H_

enum {
    /* Start here to avoid overlap with PSA_IPC_CONNECT, PSA_IPC_DISCONNECT
     * and VERSION_REQUEST */
    PSA_CRYPTO_INIT = 100,
EOF

    for my $function (@functions) {
        my $enum = uc($function);
        print $fh <<EOF;
    $enum,
EOF
    }

    print $fh <<EOF;
};

#endif /*  _PSA_FUNCTIONS_CODES_H_ */
EOF

    close($fh);
}

sub write_client_calls
{
    my ($file) = @_;

    open(my $fh, ">", $file) || die("$0: $file: $!\n");

    print $fh client_calls_header();

    for my $function (@functions) {
        my $f = $functions{$function};
        output_client($fh, $f, $function);
    }

    close($fh);
}

sub write_server_implementations
{
    my ($file) = @_;

    open(my $fh, ">", $file) || die("$0: $file: $!\n");

    print $fh server_implementations_header();

    for my $function (@functions) {
        my $f = $functions{$function};
        output_server_wrapper($fh, $f, $function);
    }

    # Now output a switch statement that calls each of the wrappers

    print $fh <<EOF;

psa_status_t psa_crypto_call(psa_msg_t msg)
{
    int ok = 0;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    int func = msg.type;

    /* We only expect a single input buffer, with everything serialised in it */
    if (msg.in_size[1] != 0 || msg.in_size[2] != 0 || msg.in_size[3] != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* We expect exactly 2 output buffers, one for size, the other for data */
    if (msg.out_size[0] != sizeof(size_t) || msg.out_size[1] == 0 ||
        msg.out_size[2] != 0 || msg.out_size[3] != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* XXX TODO: fill in out_params, using msg */
    uint8_t *in_params = NULL;
    size_t in_params_len = 0;
    uint8_t **out_params = NULL;
    size_t *out_params_len = 0;

    in_params_len = msg.in_size[0];
    in_params = malloc(in_params_len);
    if (in_params == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    /* Read the bytes from the client */
    size_t actual = psa_read(msg.handle, 0, in_params, in_params_len);
    if (actual != in_params_len) {
        free(in_params);
        return PSA_ERROR_CORRUPTION_DETECTED;
    }

    switch (func) {
        case PSA_CRYPTO_INIT:
            status = psa_crypto_init();
            ok = (status == PSA_SUCCESS);
            break;
EOF

    for my $function (@functions) {
        my $f = $functions{$function};
        my $enum = uc($function);
        print $fh <<EOF;
        case $enum:
            ok = ${function}_wrapper(in_params, in_params_len,
                                     out_params, out_params_len);
            break;
EOF
    }

    print $fh <<EOF;
    }

    free(in_params);

    return ok ? PSA_SUCCESS : PSA_ERROR_GENERIC_ERROR;
}
EOF

    close($fh);
}

sub server_implementations_header
{
    return <<'EOF';
/* THIS FILE WAS AUTO-GENERATED BY $0. DO NOT EDIT!! */

/* server implementations */

#include <stdio.h>
#include <stdlib.h>

#include <psa/crypto.h>

#include "psa_functions_codes.h"
#include "psa_sim_serialise.h"

#include "service.h"
EOF
}

sub client_calls_header
{
    return <<'EOF';
/* THIS FILE WAS AUTO-GENERATED BY $0. DO NOT EDIT!! */

/* client calls */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include <stdio.h>
#include <unistd.h>

/* Includes from psasim */
#include <client.h>
#include <util.h>
#include "psa_manifest/sid.h"
#include "psa_functions_codes.h"
#include "psa_sim_serialise.h"

/* Includes from mbedtls */
#include "mbedtls/version.h"
#include "psa/crypto.h"

#define CLIENT_PRINT(fmt, ...) \
    PRINT("Client: " fmt, ##__VA_ARGS__)

static psa_handle_t handle = -1;

int psa_crypto_call(int function,
                    uint8_t *in_params, size_t in_params_len,
                    uint8_t **out_params, size_t *out_params_len)
{
    // psa_outvec outvecs[1];
    if (handle < 0) {
        fprintf(stderr, "NOT CONNECTED\n");
        exit(1);
    }

    psa_invec invec;
    invec.base = in_params;
    invec.len = in_params_len;

    size_t max_receive = 8192;
    uint8_t *receive = malloc(max_receive);
    if (receive == NULL) {
        fprintf(stderr, "FAILED to allocate %u bytes\n", (unsigned)max_receive);
        exit(1);
    }

    size_t actual_received = 0;

    psa_outvec outvecs[2];
    outvecs[0].base = &actual_received;
    outvecs[0].len = sizeof(actual_received);
    outvecs[1].base = receive;
    outvecs[1].len = max_receive;

    psa_status_t status = psa_call(handle, function, &invec, 1, outvecs, 2);
    if (status != PSA_SUCCESS) {
        free(receive);
        return 0;
    }

    // TODO: put the returned data from psa_call into out_params/out_params_len

    return 1;   // success
}

psa_status_t psa_crypto_init(void)
{
    char mbedtls_version[18];
    uint8_t *result = NULL;
    size_t result_length;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    mbedtls_version_get_string_full(mbedtls_version);
    CLIENT_PRINT("%s", mbedtls_version);

    CLIENT_PRINT("My PID: %d", getpid());

    CLIENT_PRINT("PSA version: %u", psa_version(PSA_SID_CRYPTO_SID));
    handle = psa_connect(PSA_SID_CRYPTO_SID, 1);

    if (handle < 0) {
        CLIENT_PRINT("Couldn't connect %d", handle);
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }

    int ok = psa_crypto_call(PSA_CRYPTO_INIT, NULL, 0, &result, &result_length);
    CLIENT_PRINT("PSA_CRYPTO_INIT returned: %d", ok);

    if (!ok) {
        goto fail;
    }

    uint8_t *rpos = result;
    size_t rremain = result_length;

    ok = psasim_deserialise_begin(&rpos, &rremain);
    if (!ok) goto fail;

    ok = psasim_deserialise_psa_status_t(&rpos, &rremain, &status);
    if (!ok) goto fail;

fail:
    free(result);

    return status;
}

void mbedtls_psa_crypto_free(void)
{
    CLIENT_PRINT("Closing handle");
    psa_close(handle);
    handle = -1;
}
EOF
}

sub output_header
{
    my ($fh) = @_;

    print $fh <<EOF;
/* THIS FILE WAS AUTO-GENERATED BY $0. DO NOT EDIT!! */

#include <stdlib.h>

#include "psa/crypto.h"
#include "psa/crypto_values.h"
#include "psa_sim_serialise.h"
EOF
}

sub output_debug_functions
{
    my ($fh) = @_;

    print $fh <<EOF;

static inline char hex_digit(char nibble) {
    return (nibble < 10) ? (nibble + '0') : (nibble + 'a' - 10);
}

int hex_byte(char *p, uint8_t b)
{
    p[0] = hex_digit(b >> 4);
    p[1] = hex_digit(b & 0x0F);

    return 2;
}

int hex_uint16(char *p, uint16_t b)
{
    hex_byte(p, b >> 8);
    hex_byte(p + 2, b & 0xFF);

    return 4;
}

char human_char(uint8_t c)
{
    return (c >= ' ' && c <= '~') ? (char)c : '.';
}

void dump_buffer(const uint8_t *buffer, size_t len)
{
    char line[80];

    const uint8_t *p = buffer;

    size_t max = (len > 0xFFFF) ? 0xFFFF : len;

    for (size_t i = 0; i < max; i += 16) {

        char *q = line;

        q += hex_uint16(q, (uint16_t)i);
        *q++ = ' ';
        *q++ = ' ';

        size_t ll = (i + 16 > max) ? (max % 16) : 16;

        size_t j;
        for (j = 0; j < ll; j++) {
            q += hex_byte(q, p[i + j]);
            *q++ = ' ';
        }

        while (j++ < 16) {
            *q++ = ' ';
            *q++ = ' ';
            *q++ = ' ';
        }

        *q++ = ' ';

        for (j = 0; j < ll; j++) {
            *q++ = human_char(p[i + j]);
        }

        *q = '\\0';

        printf("%s\\n", line);
    }
}

void hex_dump(uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        printf("0x%02X ", p[i]);
    }
    printf("\\n");
}
EOF
}

sub output_server_wrapper
{
    my ($fh, $f, $name) = @_;

    my $debug = 0;

    my $ret_type = $f->{return}->{type};
    my $ret_name = $f->{return}->{name};
    my $ret_default = $f->{return}->{default};

    print $fh <<EOF;

// Returns 1 for success, 0 for failure
int ${name}_wrapper(
    uint8_t *in_params, size_t in_params_len,
    uint8_t **out_params, size_t *out_params_len)
{
    $ret_type $ret_name = $ret_default;
EOF
    # Output the variables we will need when we call the target function

    my $args = $f->{args};

    for my $i (0 .. $#$args) {
        my $arg = $args->[$i];
        my $argtype = $arg->{type};     # e.g. int, psa_algorithm_t, or "buffer"
        my $argname = $arg->{name};
        $argtype =~ s/^const //;

        if ($argtype =~ /^(const )?buffer$/) {
            my ($n1, $n2) = split(/,\s*/, $argname);
            print $fh <<EOF;
    uint8_t *$n1 = NULL;
    size_t $n2;
EOF
        } else {
            $argname =~ s/^\*//;        # Remove any leading *
            print $fh <<EOF;
    $argtype $argname;
EOF
        }
    }

    print $fh <<EOF;

    uint8_t *pos = in_params;
    size_t remaining = in_params_len;
    uint8_t *result = NULL;
    int ok;

    printf("$name: server\\n");

    ok = psasim_deserialise_begin(&pos, &remaining);
    if (!ok) {
        goto fail;
    }
EOF

    for my $i (0 .. $#$args) {
        my $arg = $args->[$i];
        my $argtype = $arg->{type};     # e.g. int, psa_algorithm_t, or "buffer"
        my $argname = $arg->{name};
        my $sep = ($i == $#$args) ? ";" : " +";
        $argtype =~ s/^const //;

        if ($argtype =~ /^(const )?buffer$/) {
            my ($n1, $n2) = split(/,\s*/, $argname);
            print $fh <<EOF;

    ok = psasim_deserialise_${argtype}(&pos, &remaining, &$n1, &$n2);
    if (!ok) {
        goto fail;
    }
EOF
        } else {
            $argname =~ s/^\*//;        # Remove any leading *
            print $fh <<EOF;

    ok = psasim_deserialise_${argtype}(&pos, &remaining, &$argname);
    if (!ok) {
        goto fail;
    }
EOF
        }
    }

    print $fh <<EOF;

    // Now we call the actual target function
EOF
    output_call($fh, $f, $name);

    my @outputs = grep($_->{is_output}, @$args);

    my $sep1 = ($#outputs < 0) ? ";" : " +";

    print $fh <<EOF;

    // NOTE: Should really check there is no overflow as we go along.
    size_t result_size =
        psasim_serialise_begin_needs()$sep1
EOF

    if ($ret_type ne "void") {
        my $sep = ($#outputs < 0) ? ";" : " +";
        print $fh <<EOF;
        psasim_serialise_${ret_type}_needs($ret_name)$sep
EOF
    }

    for my $i (0 .. $#outputs) {
        my $arg = $outputs[$i];
        die("$i: this should have been filtered out by grep") unless $arg->{is_output};
        my $argtype = $arg->{type};     # e.g. int, psa_algorithm_t, or "buffer"
        my $argname = $arg->{name};
        my $sep = ($i == $#outputs) ? ";" : " +";
        $argtype =~ s/^const //;
        $argname =~ s/^\*//;        # Remove any leading *

        print $fh <<EOF;
        psasim_serialise_${argtype}_needs($argname)$sep
EOF
    }

    print $fh <<EOF;

    result = malloc(result_size);
    if (result == NULL) goto fail;

    uint8_t *rpos = result;
    size_t rremain = result_size;

    ok = psasim_serialise_begin(&rpos, &rremain);
    if (!ok) {
        goto fail;
    }
EOF

    if ($ret_type ne "void") {
        print $fh <<EOF;

    ok = psasim_serialise_${ret_type}(&rpos, &rremain, $ret_name);
    if (!ok) {
        goto fail;
    }
EOF
    }

    my @outputs = grep($_->{is_output}, @$args);

    for my $i (0 .. $#outputs) {
        my $arg = $outputs[$i];
        die("$i: this should have been filtered out by grep") unless $arg->{is_output};
        my $argtype = $arg->{type};     # e.g. int, psa_algorithm_t, or "buffer"
        my $argname = $arg->{name};
        my $sep = ($i == $#outputs) ? ";" : " +";
        $argtype =~ s/^const //;

        if ($argtype eq "buffer") {
            print $fh <<EOF;

    ok = psasim_serialise_buffer(&rpos, &rremain, $argname);
    if (!ok) {
        goto fail;
    }
EOF
        } else {
            if ($argname =~ /^\*/) {
                $argname =~ s/^\*//;    # since it's already a pointer
            } else {
                die("$0: $argname: HOW TO OUTPUT?\n");
            }

            print $fh <<EOF;

    ok = psasim_serialise_${argtype}(&rpos, &rremain, $argname);
    if (!ok) {
        goto fail;
    }
EOF
        }
    }

    print $fh <<EOF;

    *out_params = result;
    *out_params_len = result_size;

    return 1;   // success

fail:
    free(result);
    return 0;       // This shouldn't happen!
}
EOF
}

sub output_client
{
    my ($fh, $f, $name) = @_;

    my $debug = 0;

    print $fh "\n";

    output_definition_begin($fh, $f, $name);

    my $ret_type = $f->{return}->{type};
    my $ret_name = $f->{return}->{name};
    my $ret_default = $f->{return}->{default};

    print $fh <<EOF;
{
    uint8_t *params = NULL;
    uint8_t *result = NULL;
    size_t result_length;
    $ret_type $ret_name = $ret_default;

    printf("$name: client\\n");

    size_t needed = psasim_serialise_begin_needs() +
EOF

    my $args = $f->{args};

    for my $i (0 .. $#$args) {
        my $arg = $args->[$i];
        my $argtype = $arg->{type};     # e.g. int, psa_algorithm_t, or "buffer"
        my $argname = $arg->{name};
        my $sep = ($i == $#$args) ? ";" : " +";
        $argtype =~ s/^const //;

        print $fh <<EOF;
        psasim_serialise_${argtype}_needs($argname)$sep
EOF
    }

    print $fh <<EOF;

    params = malloc(needed);
    if (params == NULL) {
        status = PSA_ERROR_INSUFFICIENT_MEMORY;
        goto fail;
    }

    uint8_t *pos = params;
    size_t remaining = needed;
    int ok;
    ok = psasim_serialise_begin(&pos, &remaining);
    if (!ok) goto fail;
EOF

    for my $i (0 .. $#$args) {
        my $arg = $args->[$i];
        my $argtype = $arg->{type};     # e.g. int, psa_algorithm_t, or "buffer"
        my $argname = $arg->{name};
        my $sep = ($i == $#$args) ? ";" : " +";
        $argtype =~ s/^const //;

        print $fh <<EOF;
    ok = psasim_serialise_${argtype}(&pos, &remaining, $argname);
    if (!ok) goto fail;
EOF
    }

    print $fh <<EOF if $debug;

    printf("client sending %d:\\n", (int)(pos - params));
    dump_buffer(params, (size_t)(pos - params));
EOF

    my $enum = uc($name);

    print $fh <<EOF;

    ok = psa_crypto_call($enum, params, (size_t)(pos - params), &result, &result_length);
    if (!ok) {
        printf("XXX server call failed\\n");
        goto fail;
    }
EOF

    print $fh <<EOF if $debug;

    printf("client receiving %d:\\n", (int)result_length);
    dump_buffer(result, result_length);
EOF

    print $fh <<EOF;

    uint8_t *rpos = result;
    size_t rremain = result_length;

    ok = psasim_deserialise_begin(&rpos, &rremain);
    if (!ok) goto fail;
EOF

    print $fh <<EOF;

    ok = psasim_deserialise_$ret_type(&rpos, &rremain, &$ret_name);
    if (!ok) goto fail;
EOF

    my @outputs = grep($_->{is_output}, @$args);

    for my $i (0 .. $#outputs) {
        my $arg = $outputs[$i];
        die("$i: this should have been filtered out by grep") unless $arg->{is_output};
        my $argtype = $arg->{type};     # e.g. int, psa_algorithm_t, or "buffer"
        my $argname = $arg->{name};
        my $sep = ($i == $#outputs) ? ";" : " +";
        $argtype =~ s/^const //;

        if ($argtype eq "buffer") {
            print $fh <<EOF;

    ok = psasim_deserialise_return_buffer(&rpos, &rremain, $argname);
    if (!ok) goto fail;
EOF
        } else {
            if ($argname =~ /^\*/) {
                $argname =~ s/^\*//;    # since it's already a pointer
            } else {
                die("$0: $argname: HOW TO OUTPUT?\n");
            }

            print $fh <<EOF;

    ok = psasim_deserialise_${argtype}(&rpos, &rremain, $argname);
    if (!ok) goto fail;
EOF
        }
    }
    print $fh <<EOF;

fail:
    free(params);
    free(result);

    return $ret_name;
}
EOF
}

sub output_declaration
{
    my ($f, $name) = @_;

    output_signature($f, $name, "declaration");
}

sub output_definition_begin
{
    my ($fh, $f, $name) = @_;

    output_signature($fh, $f, $name, "definition");
}

sub output_call
{
    my ($fh, $f, $name) = @_;

    my $ret_name = $f->{return}->{name};
    my $args = $f->{args};

    print $fh "\n    $ret_name = $name(\n";

    for my $i (0 .. $#$args) {
        my $arg = $args->[$i];
        my $argtype = $arg->{type};     # e.g. int, psa_algorithm_t, or "buffer"
        my $argname = $arg->{name};

        if ($argtype =~ /^(const )?buffer$/) {
            my ($n1, $n2) = split(/,\s*/, $argname);
            print $fh "        $n1, $n2";
        } else {
            $argname =~ s/^\*/\&/;      # Replace leading * with &
            print $fh "        $argname";
        }
        my $sep = ($i == $#$args) ? "\n    );" : ",";
        print $fh "$sep\n";
    }
}

sub output_signature
{
    my ($fh, $f, $name, $what) = @_;

    my $ret_type = $f->{return}->{type};
    my $args = $f->{args};

    my $final_sep = ($what eq "declaration") ? "\n);" : "\n)";

    print $fh "\n$ret_type $name(\n";

    for my $i (0 .. $#$args) {
        my $arg = $args->[$i];
        my $argtype = $arg->{type};             # e.g. int, psa_algorithm_t, or "buffer"
        my $ctypename = $arg->{ctypename};      # e.g. "int ", "char *"; empty for buffer
        my $argname = $arg->{name};

        if ($argtype =~ /^(const )?buffer$/) {
            my $const = length($1) ? "const " : "";
            my ($n1, $n2) = split(/,/, $argname);
            print $fh "    ${const}uint8_t *$n1, size_t $n2";
        } else {
            print $fh "    $ctypename$argname";
        }
        my $sep = ($i == $#$args) ? $final_sep : ",";
        print $fh "$sep\n";
    }
}

sub get_functions
{
    my $src = "";
    while (<DATA>) {
        chomp;
        s/\/\/.*//;
        s/\s+^//;
        s/\s+/ /g;
        $_ .= "\n";
        $src .= $_;
    }

    $src =~ s/\/\*.*?\*\///gs;

    my @src = split(/\n+/, $src);

    my @rebuild = ();
    my %funcs = ();
    for (my $i = 0; $i <= $#src; $i++) {
        my $line = $src[$i];
        if ($line =~ /^psa_status_t (psa_\w*)\(/) { # begin function definition
            #print "have one $line\n";
            while ($line !~ /;/) {
                $line .= $src[$i + 1];
                $i++;
            }
            $line =~ s/\s+/ /g;
            if ($line =~ /(\w+)\s+\b(\w+)\s*\(\s*(.*\S)\s*\)\s*[;{]/s) {
                my ($ret_type, $func, $args) = ($1, $2, $3);
                my $copy = $line;
                $copy =~ s/{$//;
                my $f = {
                    "orig" => $copy,
                };

                my @args = split(/\s*,\s*/, $args);

                my $ret_name = "";
                $ret_name = "status" if $ret_type eq "psa_status_t";
                die("ret_name for $ret_type?") unless length($ret_name);
                my $ret_default = "";
                $ret_default = "PSA_ERROR_CORRUPTION_DETECTED" if $ret_type eq "psa_status_t";
                die("ret_default for $ret_type?") unless length($ret_default);

                #print "FUNC $func RET_NAME $ret_name RET_TYPE $ret_type ARGS (", join("; ", @args), ")\n";

                $f->{return} = {
                    "type" => $ret_type,
                    "default" => $ret_default,
                    "name" => $ret_name,
                };
                $f->{args} = [];
                # psa_algorithm_t alg; const uint8_t *input; size_t input_length; uint8_t *hash; size_t hash_size; size_t *hash_length
                for (my $i = 0; $i <= $#args; $i++) {
                    my $arg = $args[$i];
                    # "type" => "psa_algorithm_t",
                    # "ctypename" => "psa_algorithm_t ",
                    # "name" => "alg",
                    # "is_output" => 0,
                    my ($type, $ctype, $name, $is_output);
                    if ($arg =~ /^(\w+)\s+(\w+)$/) {    # e.g. psa_algorithm_t alg
                        ($type, $name) = ($1, $2);
                        $ctype = $type . " ";
                        $is_output = 0;
                    } elsif ($arg =~ /^((const)\s+)?uint8_t\s*\*\s*(\w+)$/) {
                        $type = "buffer";
                        $is_output = (length($1) == 0) ? 1 : 0;
                        $type = "const buffer" if !$is_output;
                        $ctype = "";
                        $name = $3;
                        #print("$arg: $name: might be a buffer?\n");
                        die("$arg: not a buffer 1!\n") if $i == $#args;
                        my $next = $args[$i + 1];
                        die("$arg: not a buffer 2!\n") if $next !~ /^size_t\s+(${name}_\w+)$/;
                        $i++;                   # We're using the next param here
                        my $nname = $1;
                        $name .= ", " . $nname;
                    } elsif ($arg =~ /^((const)\s+)?(\w+)\s*\*(\w+)$/) {
                        ($type, $name) = ($3, "*" . $4);
                        $ctype = $1 . $type . " ";
                        $is_output = (length($1) == 0) ? 1 : 0;
                    } else {
                        die("ARG HELP $arg\n");
                    }
                    #print "$arg => <$type><$ctype><$name><$is_output>\n";
                    push(@{$f->{args}}, {
                        "type" => $type,
                        "ctypename" => $ctype,
                        "name" => $name,
                        "is_output" => $is_output,
                    });
                }
                $funcs{$func} = $f;
            } else {
                die("FAILED");
            }
            push(@rebuild, $line);
        } elsif ($line =~ /^static psa_\w+_t (psa_\w*)\(/) { # begin function definition
             # IGNORE static functions
        } else {
            if ($line =~ /psa_/) {
                print "NOT PARSED: $line\n";
exit;
            }
            push(@rebuild, $line);
        }
    }

    #print ::Dumper(\%funcs);
    #exit;

    return %funcs;
}

__END__
/** Calculate the hash (digest) of a message.
 *
 * \note To verify the hash of a message against an
 *       expected value, use psa_hash_compare() instead.
 *
 * \param alg               The hash algorithm to compute (\c PSA_ALG_XXX value
 *                          such that #PSA_ALG_IS_HASH(\p alg) is true).
 * \param[in] input         Buffer containing the message to hash.
 * \param input_length      Size of the \p input buffer in bytes.
 * \param[out] hash         Buffer where the hash is to be written.
 * \param hash_size         Size of the \p hash buffer in bytes.
 * \param[out] hash_length  On success, the number of bytes
 *                          that make up the hash value. This is always
 *                          #PSA_HASH_LENGTH(\p alg).
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         \p alg is not supported or is not a hash algorithm.
 * \retval #PSA_ERROR_INVALID_ARGUMENT \emptydescription
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         \p hash_size is too small
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY \emptydescription
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE \emptydescription
 * \retval #PSA_ERROR_HARDWARE_FAILURE \emptydescription
 * \retval #PSA_ERROR_CORRUPTION_DETECTED \emptydescription
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_hash_compute(psa_algorithm_t alg,
                              const uint8_t *input,
                              size_t input_length,
                              uint8_t *hash,
                              size_t hash_size,
                              size_t *hash_length);

/* XXX We put this next one in place to check we ignore static functions
 *     when we eventually read all this from a real header file
 */

/** Return an initial value for a hash operation object.
 */
static psa_hash_operation_t psa_hash_operation_init(void);

/* XXX Back to normal function declarations */

/** Set up a multipart hash operation.
 *
 * The sequence of operations to calculate a hash (message digest)
 * is as follows:
 * -# Allocate an operation object which will be passed to all the functions
 *    listed here.
 * -# Initialize the operation object with one of the methods described in the
 *    documentation for #psa_hash_operation_t, e.g. #PSA_HASH_OPERATION_INIT.
 * -# Call psa_hash_setup() to specify the algorithm.
 * -# Call psa_hash_update() zero, one or more times, passing a fragment
 *    of the message each time. The hash that is calculated is the hash
 *    of the concatenation of these messages in order.
 * -# To calculate the hash, call psa_hash_finish().
 *    To compare the hash with an expected value, call psa_hash_verify().
 *
 * If an error occurs at any step after a call to psa_hash_setup(), the
 * operation will need to be reset by a call to psa_hash_abort(). The
 * application may call psa_hash_abort() at any time after the operation
 * has been initialized.
 *
 * After a successful call to psa_hash_setup(), the application must
 * eventually terminate the operation. The following events terminate an
 * operation:
 * - A successful call to psa_hash_finish() or psa_hash_verify().
 * - A call to psa_hash_abort().
 *
 * \param[in,out] operation The operation object to set up. It must have
 *                          been initialized as per the documentation for
 *                          #psa_hash_operation_t and not yet in use.
 * \param alg               The hash algorithm to compute (\c PSA_ALG_XXX value
 *                          such that #PSA_ALG_IS_HASH(\p alg) is true).
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         \p alg is not a supported hash algorithm.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         \p alg is not a hash algorithm.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY \emptydescription
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE \emptydescription
 * \retval #PSA_ERROR_HARDWARE_FAILURE \emptydescription
 * \retval #PSA_ERROR_CORRUPTION_DETECTED \emptydescription
 * \retval #PSA_ERROR_BAD_STATE
 *         The operation state is not valid (it must be inactive), or
 *         the library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_hash_setup(psa_hash_operation_t *operation,
                            psa_algorithm_t alg);

/** Add a message fragment to a multipart hash operation.
 *
 * The application must call psa_hash_setup() before calling this function.
 *
 * If this function returns an error status, the operation enters an error
 * state and must be aborted by calling psa_hash_abort().
 *
 * \param[in,out] operation Active hash operation.
 * \param[in] input         Buffer containing the message fragment to hash.
 * \param input_length      Size of the \p input buffer in bytes.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY \emptydescription
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE \emptydescription
 * \retval #PSA_ERROR_HARDWARE_FAILURE \emptydescription
 * \retval #PSA_ERROR_CORRUPTION_DETECTED \emptydescription
 * \retval #PSA_ERROR_BAD_STATE
 *         The operation state is not valid (it must be active), or
 *         the library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_hash_update(psa_hash_operation_t *operation,
                             const uint8_t *input,
                             size_t input_length);

/** Finish the calculation of the hash of a message.
 *
 * The application must call psa_hash_setup() before calling this function.
 * This function calculates the hash of the message formed by concatenating
 * the inputs passed to preceding calls to psa_hash_update().
 *
 * When this function returns successfully, the operation becomes inactive.
 * If this function returns an error status, the operation enters an error
 * state and must be aborted by calling psa_hash_abort().
 *
 * \warning Applications should not call this function if they expect
 *          a specific value for the hash. Call psa_hash_verify() instead.
 *          Beware that comparing integrity or authenticity data such as
 *          hash values with a function such as \c memcmp is risky
 *          because the time taken by the comparison may leak information
 *          about the hashed data which could allow an attacker to guess
 *          a valid hash and thereby bypass security controls.
 *
 * \param[in,out] operation     Active hash operation.
 * \param[out] hash             Buffer where the hash is to be written.
 * \param hash_size             Size of the \p hash buffer in bytes.
 * \param[out] hash_length      On success, the number of bytes
 *                              that make up the hash value. This is always
 *                              #PSA_HASH_LENGTH(\c alg) where \c alg is the
 *                              hash algorithm that is calculated.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of the \p hash buffer is too small. You can determine a
 *         sufficient buffer size by calling #PSA_HASH_LENGTH(\c alg)
 *         where \c alg is the hash algorithm that is calculated.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY \emptydescription
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE \emptydescription
 * \retval #PSA_ERROR_HARDWARE_FAILURE \emptydescription
 * \retval #PSA_ERROR_CORRUPTION_DETECTED \emptydescription
 * \retval #PSA_ERROR_BAD_STATE
 *         The operation state is not valid (it must be active), or
 *         the library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_hash_finish(psa_hash_operation_t *operation,
                             uint8_t *hash,
                             size_t hash_size,
                             size_t *hash_length);

/** Finish the calculation of the hash of a message and compare it with
 * an expected value.
 *
 * The application must call psa_hash_setup() before calling this function.
 * This function calculates the hash of the message formed by concatenating
 * the inputs passed to preceding calls to psa_hash_update(). It then
 * compares the calculated hash with the expected hash passed as a
 * parameter to this function.
 *
 * When this function returns successfully, the operation becomes inactive.
 * If this function returns an error status, the operation enters an error
 * state and must be aborted by calling psa_hash_abort().
 *
 * \note Implementations shall make the best effort to ensure that the
 * comparison between the actual hash and the expected hash is performed
 * in constant time.
 *
 * \param[in,out] operation     Active hash operation.
 * \param[in] hash              Buffer containing the expected hash value.
 * \param hash_length           Size of the \p hash buffer in bytes.
 *
 * \retval #PSA_SUCCESS
 *         The expected hash is identical to the actual hash of the message.
 * \retval #PSA_ERROR_INVALID_SIGNATURE
 *         The hash of the message was calculated successfully, but it
 *         differs from the expected hash.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY \emptydescription
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE \emptydescription
 * \retval #PSA_ERROR_HARDWARE_FAILURE \emptydescription
 * \retval #PSA_ERROR_CORRUPTION_DETECTED \emptydescription
 * \retval #PSA_ERROR_BAD_STATE
 *         The operation state is not valid (it must be active), or
 *         the library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_hash_verify(psa_hash_operation_t *operation,
                             const uint8_t *hash,
                             size_t hash_length);

/** Abort a hash operation.
 *
 * Aborting an operation frees all associated resources except for the
 * \p operation structure itself. Once aborted, the operation object
 * can be reused for another operation by calling
 * psa_hash_setup() again.
 *
 * You may call this function any time after the operation object has
 * been initialized by one of the methods described in #psa_hash_operation_t.
 *
 * In particular, calling psa_hash_abort() after the operation has been
 * terminated by a call to psa_hash_abort(), psa_hash_finish() or
 * psa_hash_verify() is safe and has no effect.
 *
 * \param[in,out] operation     Initialized hash operation.
 *
 * \retval #PSA_SUCCESS \emptydescription
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE \emptydescription
 * \retval #PSA_ERROR_HARDWARE_FAILURE \emptydescription
 * \retval #PSA_ERROR_CORRUPTION_DETECTED \emptydescription
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_hash_abort(psa_hash_operation_t *operation);

/** Clone a hash operation.
 *
 * This function copies the state of an ongoing hash operation to
 * a new operation object. In other words, this function is equivalent
 * to calling psa_hash_setup() on \p target_operation with the same
 * algorithm that \p source_operation was set up for, then
 * psa_hash_update() on \p target_operation with the same input that
 * that was passed to \p source_operation. After this function returns, the
 * two objects are independent, i.e. subsequent calls involving one of
 * the objects do not affect the other object.
 *
 * \param[in] source_operation      The active hash operation to clone.
 * \param[in,out] target_operation  The operation object to set up.
 *                                  It must be initialized but not active.
 *
 * \retval #PSA_SUCCESS \emptydescription
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE \emptydescription
 * \retval #PSA_ERROR_HARDWARE_FAILURE \emptydescription
 * \retval #PSA_ERROR_CORRUPTION_DETECTED \emptydescription
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY \emptydescription
 * \retval #PSA_ERROR_BAD_STATE
 *         The \p source_operation state is not valid (it must be active), or
 *         the \p target_operation state is not valid (it must be inactive), or
 *         the library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_hash_clone(const psa_hash_operation_t *source_operation,
                            psa_hash_operation_t *target_operation);

/** Calculate the hash (digest) of a message and compare it with a
 * reference value.
 *
 * \param alg               The hash algorithm to compute (\c PSA_ALG_XXX value
 *                          such that #PSA_ALG_IS_HASH(\p alg) is true).
 * \param[in] input         Buffer containing the message to hash.
 * \param input_length      Size of the \p input buffer in bytes.
 * \param[out] hash         Buffer containing the expected hash value.
 * \param hash_length       Size of the \p hash buffer in bytes.
 *
 * \retval #PSA_SUCCESS
 *         The expected hash is identical to the actual hash of the input.
 * \retval #PSA_ERROR_INVALID_SIGNATURE
 *         The hash of the message was calculated successfully, but it
 *         differs from the expected hash.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         \p alg is not supported or is not a hash algorithm.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         \p input_length or \p hash_length do not match the hash size for \p alg
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY \emptydescription
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE \emptydescription
 * \retval #PSA_ERROR_HARDWARE_FAILURE \emptydescription
 * \retval #PSA_ERROR_CORRUPTION_DETECTED \emptydescription
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_hash_compare(psa_algorithm_t alg,
                              const uint8_t *input,
                              size_t input_length,
                              const uint8_t *hash,
                              size_t hash_length);
