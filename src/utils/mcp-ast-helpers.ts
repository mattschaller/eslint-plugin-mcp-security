import { TSESTree, AST_NODE_TYPES } from '@typescript-eslint/utils';

/**
 * Check if a CallExpression is a `.tool()` method call.
 */
export function isToolMethodCall(
  node: TSESTree.CallExpression,
): boolean {
  return (
    node.callee.type === AST_NODE_TYPES.MemberExpression &&
    node.callee.property.type === AST_NODE_TYPES.Identifier &&
    node.callee.property.name === 'tool'
  );
}

/**
 * Extract the description node from a `.tool()` call.
 *
 * MCP SDK signatures:
 *   server.tool(name, handler)
 *   server.tool(name, description, handler)
 *   server.tool(name, schema, handler)
 *   server.tool(name, description, schema, handler)
 *
 * The description is the 2nd argument when it's a string literal
 * or template literal (as opposed to an object/Zod schema).
 */
export function getToolDescriptionNode(
  node: TSESTree.CallExpression,
): TSESTree.Literal | TSESTree.TemplateLiteral | null {
  if (node.arguments.length < 2) return null;

  const secondArg = node.arguments[1];

  if (
    secondArg.type === AST_NODE_TYPES.Literal &&
    typeof secondArg.value === 'string'
  ) {
    return secondArg;
  }

  if (secondArg.type === AST_NODE_TYPES.TemplateLiteral) {
    return secondArg;
  }

  return null;
}

/**
 * Extract the static text from a string literal or template literal.
 * For template literals, only the static quasi parts are joined
 * (dynamic expressions are ignored).
 */
export function getStaticStringValue(
  node: TSESTree.Literal | TSESTree.TemplateLiteral,
): string {
  if (node.type === AST_NODE_TYPES.Literal) {
    return String(node.value);
  }

  return node.quasis.map((q) => q.value.cooked ?? q.value.raw).join('');
}

/**
 * Get the handler function node from a .tool() call.
 * The handler is always the last argument.
 */
export function getToolHandlerNode(
  node: TSESTree.CallExpression,
): TSESTree.ArrowFunctionExpression | TSESTree.FunctionExpression | null {
  const lastArg = node.arguments[node.arguments.length - 1];
  if (!lastArg) return null;

  if (
    lastArg.type === AST_NODE_TYPES.ArrowFunctionExpression ||
    lastArg.type === AST_NODE_TYPES.FunctionExpression
  ) {
    return lastArg;
  }

  return null;
}
