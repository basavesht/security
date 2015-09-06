package com.bosch.security;

public class B extends A {

	static {
		System.out.println("B1");
	}
	
	public B () {
		System.out.println("B2");
	}
	
	{
		System.out.println("B3");
	}
}
