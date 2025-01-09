a = b;
b = c();
d(a);
e(b);
// a = src1 + src2
// b = src3
// c = a + b

// c = a
// if (tst)
//     c = sanit(c)

// sink = c


// z = sanit(b)
// x = sanit(z)

// if (tst)
//     a = sanit(x)
// else
//     c = sanit(x)
//     d = sanit(c)

// e = a + d
// f = sanit(e)

// // source = a
// // sanitizers = san
// // sink = b


// // if (b) {
// //     a = san
// // }
// // else {
// //     a = non - san
// // }

// // "a" 

// // b = a

// tip: variables might be tainted or not before they reach a sink
