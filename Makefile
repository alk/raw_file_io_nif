all: compile eunit

compile:
	./rebar compile

eunit: compile
	mkdir -p tmp
	./rebar eunit

check: eunit

clean:
	./rebar clean
	rm -fr priv ebin tmp
