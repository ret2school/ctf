/**
 * Change the flag below until it compiles correctly on TypeScript 5.1.6 :)
 */
const flag = '______________________________________________________________'
/* Do not change anything below */
type s1 = 'eZ!gjyTdSLcJ3{!Y_pTcMqW7qu{cMoyb04JXFHUaXx{8gTCIwIGE-AAWb1_wu32{'
type s2 = 'HuuMKaxLVHVqC6NSB1Rwl2WC1F7zkxxrxAuZFpPogbBd4LGGgBfK9!eUaaSIuqJK'
type chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ{_-!}'
type eight = 8
type sixtyseven = 67

type string_to_chars<
	IMGccnTsvjUQLwrf extends string,
	acc extends string[] = []
> = IMGccnTsvjUQLwrf extends `${infer head}${infer rest}`
	? string_to_chars<rest, [...acc, head]>
    : acc

type map_chars<
	pmdPNolgYxglUHyx extends string[],
	acc extends number[] = [],
	TkUOlgwCjrqLMqJJ = {}
> = acc['length'] extends pmdPNolgYxglUHyx['length']
	? TkUOlgwCjrqLMqJJ
	: map_chars<
			pmdPNolgYxglUHyx,
			[...acc, any],
                        TkUOlgwCjrqLMqJJ & {
			    // on mappe chaque char vers l'index courant
				[_ in pmdPNolgYxglUHyx[acc['length']]]: acc['length']
			}
	  >
type global_mapping = map_chars<string_to_chars<chars>>
type chars_to_numbers<
	mapping extends {
		[k in string]: number
	},
	keys extends (keyof mapping)[],
	acc extends number[] = []
> = acc['length'] extends keys['length']
	? acc
	: chars_to_numbers<
			mapping,
			keys,
			[...acc, mapping[keys[acc['length']]]]
    >

// To get true both types in argument should be the same    
type equality<T1, T2> = (<T>() => T extends T1 ? 1 : 2) extends <T>() => T extends T2 ? 1 : 2
	? true
    : false


type head<QjZYcNISkUIPleAj extends unknown[]> = QjZYcNISkUIPleAj[0]

type tail<BEQYeYFiitEfVaco extends unknown[]> = [any, ...BEQYeYFiitEfVaco][BEQYeYFiitEfVaco['length']]

type first_elements<
	list extends unknown[],
	nb_elements extends number,
	acc extends unknown[] = []
> = acc['length'] extends nb_elements
	? acc
	: first_elements<
			list,
			nb_elements,
			[...acc, list[acc['length']]]
	  >
type last_elements<
	list extends unknown[],
	nb_elements extends number,
	acc extends unknown[] = []
> = acc['length'] extends nb_elements
	? acc
	: last_elements<
			list,
			nb_elements,
			[[...acc, any, ...list][list['length']], ...acc]
	  >
type tail_plus_first_elements<list extends unknown[], nb_elements extends number> = [
	tail<list>,
	...first_elements<list, nb_elements>
]
type last_elements_plus_head<list extends unknown[], nb_elements extends number> = [
	...last_elements<list, nb_elements>,
	head<list>
]

// range<5> returns the list [0,1,2,3,4]

type range<
	n extends number,
	acc extends unknown[] = []
> = n extends acc['length']
	? acc
    : range<n, [...acc, acc['length']]>

    
type map_numbers_to_unknown<
	n, 
	acc extends unknown[] = [],
	mapping = {}
> = acc['length'] extends n
	? mapping
	: map_numbers_to_unknown<
			n,
			[...acc, any],
			mapping & {
				[_ in acc['length']]: unknown
			}
	  >
// @ts-ignore

    // minus_one<n> returns the element with index n in [any] ++ range<n>, i.e. n-1 !!
    
type minus_one<n extends number> = [any, ...range<n>][n]

type range_67 = range<sixtyseven>
type incr = last_elements_plus_head<range_67, minus_one<sixtyseven>>
type decr = tail_plus_first_elements<range_67, minus_one<sixtyseven>>
type add_modulo_67<n extends number, m extends number> = m extends 0
	? n
    : add_modulo_67<incr[n], decr[m]> // the first list increments, the second decrements, the first get back to zero when it reach 66
type mult_modulo_67<
	m extends number,
	n extends number,
	acc extends number = 0
> = n extends 0
	? acc
	: mult_modulo_67<
			m,
			decr[n],
			add_modulo_67<acc, m>
    >
    
type read_matrix<
	arg extends unknown[],
	eight1 extends number = eight,
	eight2 extends number = eight,
	m extends unknown[][] = [],
	cur_row extends unknown[] = [],
	i extends unknown[] = []
> = m['length'] extends eight1
	? m
	: cur_row['length'] extends eight2
	? read_matrix<
			arg,
			eight1,
			eight2,
			[...m, cur_row],
			[],
			i
	  >
	: read_matrix<
			arg,
			eight1,
			eight2,
			m,
			[...cur_row, arg[i['length']]],
			[...i, any]
	  >
type matrix<type_vals, n extends number, m extends number> = {
	[i in keyof map_numbers_to_unknown<n>]: {
		[j in keyof map_numbers_to_unknown<m>]: type_vals
	}
}
type sum_mod_67<
	tab extends ArrayLike<number>,
	acc extends number = 0,
	i extends unknown[] = []
> = i['length'] extends tab['length']
	? acc
	: sum_mod_67<
			tab,
			add_modulo_67<acc, tab[i['length']]>,
			[...i, any]
	  >
type mult_matrix<
	M1 extends matrix<number, eight1, eight2>,
	M2 extends matrix<number, eight2, eight3>,
	eight1 extends number = eight,
	eight2 extends number = eight,
	eight3 extends number = eight
> = {
	[i in keyof map_numbers_to_unknown<eight1>]: {
		[k in keyof map_numbers_to_unknown<eight3>]: sum_mod_67<
			{
				[j in keyof map_numbers_to_unknown<eight2>]: mult_modulo_67<
					M1[i][j],
					M2[j][k]
				>
			} & {
				length: eight2
			}
		>
	}
}
type string_to_matrix<s extends string> = read_matrix<
	chars_to_numbers<global_mapping, string_to_chars<s>>
>

type Mflag = string_to_matrix<typeof flag>

function isTheFlagCorrect(
    good: equality<
	// The two types below should be the same
	// We need to solve AX = XB in Z/67Z!
		mult_matrix<string_to_matrix<s1>, Mflag>,
		mult_matrix<Mflag, string_to_matrix<s2>>
	>,
	flag: string
) {
	if (good) {
		console.log('Correct, the flag is', flag)
	} else {
		console.log('Wrong!')
	}
}
isTheFlagCorrect(true, flag)
