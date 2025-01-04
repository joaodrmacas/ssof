from abc import ABC, abstractmethod

class Type(ABC):
    """
    Abstract base class for all types in the AST.
    """
    @abstractmethod
    def accept(self, visitor):
        pass


class ProgramType(Type):
    def __init__(self, body):
        self.body = body

    def accept(self, visitor):
        return visitor.visit_program(self)


class ExpressionType(Type):
    def __init__(self, expression):
        self.expression = expression

    def accept(self, visitor):
        return visitor.visit_expression(self)


class VariableDeclarationType(Type):
    def __init__(self, declarations):
        self.declarations = declarations

    def accept(self, visitor):
        return visitor.visit_variable_declaration(self)


class AssignmentExpressionType(Type):
    def __init__(self, left, right):
        self.left = left
        self.right = right

    def accept(self, visitor):
        return visitor.visit_assignment_expression(self)


class CallExpressionType(Type):
    def __init__(self, callee, arguments):
        self.callee = callee
        self.arguments = arguments

    def accept(self, visitor):
        return visitor.visit_call_expression(self)
    
    #g eu vou dar commit ok? e mando te repo
