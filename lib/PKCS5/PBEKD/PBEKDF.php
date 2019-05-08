<?php

declare(strict_types = 1);

namespace Sop\PKCS5\PBEKD;

/**
 * Base class for key derivation functions used in password-based cryptography.
 *
 * @see https://tools.ietf.org/html/rfc2898#section-5
 */
abstract class PBEKDF
{
    /**
     * Derive a key from the password.
     *
     * @param string $password Password
     * @param string $salt     Salt
     * @param int    $count    Iteration count
     * @param int    $length   Derived key length
     *
     * @return string Key with a size of $length
     */
    abstract public function derive(string $password, string $salt, int $count,
        int $length): string;
}
