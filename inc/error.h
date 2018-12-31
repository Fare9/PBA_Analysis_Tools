#ifndef ERROR_H
#define ERROR_H

#include "incs.h"

namespace exception_t {

	class error :  public std::exception
	{
	public:
		error (const std::string& msg) : _msg(msg) {}

		virtual const char* what() const noexcept override
		{
			return _msg.c_str();
		}

	private:
		std::string _msg;
	};

}

#endif