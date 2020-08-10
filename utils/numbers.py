def to_int(amt_str):
	try:
		assert(not amt_str.isalpha())
		amt = int(amt_str)
		assert(amt >= 0)
		return amt

	except ValueError:
		return None
	except AssertionError:
		return None

def to_float(amt_str):
	try:
		assert(not amt_str.isalpha())
		amt = float(amt_str)
		assert(amt >= 0)
		return amt

	except ValueError:
		return None
	except AssertionError:
		return None
