all: compile eunit

compile:
	./rebar compile

eunit: compile
	mkdir -p tmp
	./rebar eunit

check: eunit

brief_check:
	ONLY_BRIEF_TESTS=1 $(MAKE) eunit

clean:
	./rebar clean
	rm -fr priv ebin tmp
