<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\PKCS5\HashFunc\HashFunc;
use Sop\PKCS5\HashFunc\MD5;

/**
 * @group pbe
 * @group hash
 *
 * @internal
 */
class PBEMD5Test extends TestCase
{
    /**
     * @return HashFunc
     */
    public function testCreate()
    {
        $func = new MD5();
        $this->assertInstanceOf(HashFunc::class, $func);
        return $func;
    }

    /**
     * @depends testCreate
     *
     * @param HashFunc $func
     */
    public function testLength(HashFunc $func)
    {
        $this->assertEquals(16, $func->length());
    }

    /**
     * @depends testCreate
     *
     * @param HashFunc $func
     */
    public function testHash(HashFunc $func)
    {
        static $data = 'DATA';
        $expected = hash('md5', $data, true);
        $this->assertEquals($expected, $func($data));
    }
}
