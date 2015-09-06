package com.bosch.security;

public class A {

	static {
		System.out.println("A1");
	}
	
	public A () {
		System.out.println("A2");
	}
	
	{
		System.out.println("A3");
	}
}
