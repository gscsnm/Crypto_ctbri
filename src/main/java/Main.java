package main.java;

import java.security.SecureRandom;
import java.util.function.BinaryOperator;

import org.spongycastle.crypto.digests.SHA512Digest;
import org.spongycastle.util.encoders.Hex;

public class Main {

	public static void main(String[] args) {
		// TODO �Զ����ɵķ������

		String va = "123456789";
		String se = "123456";
		
		System.out.println("���������ǣ�");
		System.out.println(va);
		System.out.println("�����ǣ�");
		System.out.println(se);
		
		//1-���������
		SecureRandom random = new SecureRandom();
		System.out.println();
		System.out.println("1-��������� \n ������ǣ�");
		System.out.println(random.nextInt());
		

		
		//4-3 Sha3 Keccak256
		byte [] vaa = va.getBytes();
		System.out.println();
		System.out.println("4-3 Sha3 Keccak256��");
		System.out.print("ԭ���ǣ�");
		System.out.println(va);
		System.out.println("sha3������");
		System.out.println(new String(Hex.encode(HashUtil.sha3(vaa))));
		
		
		//4-4 RIPEMD160
		System.out.println();
		System.out.println("4-4  RIPEMD160��");
		System.out.print("ԭ���ǣ�");
		System.out.println(va);
		System.out.println("RIPEMD160������");
		System.out.println(new String(Hex.encode(HashUtil.ripemd160(vaa))));
		
		
		//4-1 HMAC-SHA512
		System.out.println();
		System.out.println("4-1 HMAC-SHA512��");
		System.out.print("ԭ���ǣ�");
		System.out.println(va);
		System.out.println("HMAC-SHA512������");
		byte [] buf = HashUtil.hmacSha512(se.getBytes(), vaa);
		System.out.println(new String(Hex.encode(buf)));
		byte [] buf1 = HashUtil.hmacSha512(se.getBytes(), "".getBytes());
		System.out.println(new String(Hex.encode(buf1)));
		
	}

}


