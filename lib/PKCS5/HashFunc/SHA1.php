<?php

declare(strict_types = 1);

namespace Sop\PKCS5\HashFunc;

/**
 * SHA1 hash function.
 */
class SHA1 extends HashFunc
{
    /**
     * Constructor.
     */
    public function __construct()
    {
        $this->_length = 20;
    }

    /**
     * {@inheritdoc}
     */
    public function hash(string $data): string
    {
        return sha1($data, true);
    }
}
