<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\PKCS5\HashFunc\MD5;
use Sop\PKCS5\PBEKD\PBEKDF;
use Sop\PKCS5\PBEKD\PBEKDF1;

/**
 * @group pbe
 * @group kdf
 *
 * @internal
 */
class PBEKDF1Test extends TestCase
{
    /**
     * @return PBEKDF
     */
    public function testCreate()
    {
        $kdf = new PBEKDF1(new MD5());
        $this->assertInstanceOf(PBEKDF::class, $kdf);
        return $kdf;
    }

    /**
     * @depends testCreate
     *
     * @param PBEKDF $kdf
     */
    public function testDerive(PBEKDF $kdf)
    {
        $key = $kdf->derive('password', 'salt', 8, 16);
        $this->assertEquals(16, strlen($key));
    }

    /**
     * @depends testCreate
     *
     * @param PBEKDF $kdf
     */
    public function testDeriveShort(PBEKDF $kdf)
    {
        $key = $kdf->derive('password', 'salt', 8, 10);
        $this->assertEquals(10, strlen($key));
    }

    /**
     * @depends testCreate
     *
     * @param PBEKDF $kdf
     */
    public function testKeyTooLong(PBEKDF $kdf)
    {
        $this->expectException(\LogicException::class);
        $kdf->derive('password', 'salt', 1, 17);
    }
}
