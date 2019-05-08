<?php

declare(strict_types = 1);

namespace Sop\PKCS5\HashFunc;

/**
 * MD5 hash function.
 */
class MD5 extends HashFunc
{
    /**
     * Constructor.
     */
    public function __construct()
    {
        $this->_length = 16;
    }

    /**
     * {@inheritdoc}
     */
    public function hash(string $data): string
    {
        return md5($data, true);
    }
}
