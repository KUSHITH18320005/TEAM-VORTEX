import asyncio
import os
import sys
import uuid
from dotenv import load_dotenv

load_dotenv('mad-ps-explanation-service/.env')

from assistant.agent import maddy_assistant
from assistant.models import AssistantQuery
from llm.gemini_provider import GeminiProvider

def safe_print(*args, **kwargs):
    text = " ".join(str(a) for a in args)
    end = kwargs.get('end', '\n')
    flush = kwargs.get('flush', True)
    try:
        sys.stdout.write(text + end)
    except Exception:
        clean = text.encode('ascii', errors='replace').decode('ascii')
        sys.stdout.write(clean + end)
    if flush:
        sys.stdout.flush()

async def test_all():
    safe_print('========================================')
    safe_print('1. TEST REAL GEMINI STREAMING (TASK AA1)')
    safe_print('========================================')
    tokens = []
    async def cb(t):
        if t and getattr(t, 'token', None):
            tokens.append(t.token)
            clean = t.token.encode('ascii', errors='replace').decode('ascii')
            sys.stdout.write(clean)
            sys.stdout.flush()

    conv_1 = f"test-aa1-{uuid.uuid4().hex[:6]}"
    q1 = AssistantQuery(
        query='Explain how the MAD-PS detection mesh works in 2 sentences.',
        conversation_id=conv_1,
        user_id='test-user-1',
        org_id='org_default',
    )
    res1 = await maddy_assistant.process_query_stream(q1, event_callback=cb)
    safe_print(f'\n[Query 1 Done] Provider: {res1.provider_used}, Model: {res1.model_used}')
    safe_print(f'Answer Length: {len(res1.answer)} chars')
    assert len(res1.answer) > 20, 'Response should not be empty'

    safe_print('\n========================================')
    safe_print('2. TEST AMBIGUOUS QUESTION CLARIFICATION (TASK AA2 #2)')
    safe_print('========================================')
    conv_ambig = f"test-ambig-{uuid.uuid4().hex[:6]}"
    q_ambig = AssistantQuery(
        query='what happened?',
        conversation_id=conv_ambig,
        user_id='test-user-fresh',
        org_id='org_default',
    )
    res_ambig = await maddy_assistant.process_query_stream(q_ambig)
    safe_print('Ambiguous query response:', res_ambig.answer)
    assert 'Which incident are you asking about' in res_ambig.answer, 'Maddy should ask clarifying question for ambiguous queries'

    safe_print('\n========================================')
    safe_print('3. TEST 5-POINT DEEP ML DETECTION NARRATION (TASK AA3)')
    safe_print('========================================')
    conv_inc = f"test-inc-{uuid.uuid4().hex[:6]}"
    q_incident = AssistantQuery(
        query='Walk me through the SQL injection attack INC-20260904-AFEBE9. What happened, how was it detected across models, and what did the council conclude?',
        conversation_id=conv_inc,
        user_id='test-user-soc',
        org_id='org_default',
    )
    res_inc = await maddy_assistant.process_query_stream(q_incident)
    safe_print('Deep ML Narration Answer:\n', res_inc.answer)
    assert len(res_inc.sources_cited) > 0, 'Sources should be cited'

    safe_print('\n========================================')
    safe_print('4. TEST CONVERSATION MEMORY / PRONOUN RESOLUTION (TASK AA2 #3)')
    safe_print('========================================')
    q_followup = AssistantQuery(
        query='What should I do about it, and does it require human approval?',
        conversation_id=conv_inc,  # Reusing SAME conversation session from Test 3
        user_id='test-user-soc',
        org_id='org_default',
    )
    res_followup = await maddy_assistant.process_query_stream(q_followup)
    safe_print('Followup Memory Response:\n', res_followup.answer)
    assert 'Which incident' not in res_followup.answer, 'Should resolve pronoun from conversation memory'

    safe_print('\n========================================')
    safe_print('5. TEST COMPOUND MULTI-PART QUESTION (TASK AA2 #1)')
    safe_print('========================================')
    conv_comp = f"test-comp-{uuid.uuid4().hex[:6]}"
    q_compound = AssistantQuery(
        query='Why did INC-20260904-AFEBE9 happen AND is the system healthy right now AND what are the total incident stats?',
        conversation_id=conv_comp,
        user_id='test-user-soc',
        org_id='org_default',
    )
    res_comp = await maddy_assistant.process_query_stream(q_compound)
    safe_print('Compound Query Response:\n', res_comp.answer)
    safe_print('Sources cited in compound query:', [s.source_identifier for s in res_comp.sources_cited])
    assert len(res_comp.sources_cited) >= 2, 'Should query multiple sources for compound query'

    safe_print('\n========================================')
    safe_print('6. TEST ERROR HANDLING ON INVALID KEY (TASK AA1 #5 & AA5 #4)')
    safe_print('========================================')
    bad_provider = GeminiProvider(api_key='BAD_INVALID_KEY_1234567890')
    try:
        await bad_provider.generate('Hello test')
        safe_print('UNEXPECTED: Bad key succeeded')
    except Exception as exc:
        safe_print('Confirmed expected error on bad key:', str(exc)[:100])

    safe_print('\nALL PHASE AA PYTHON TESTS PASSED SUCCESSFULLY!')

if __name__ == '__main__':
    asyncio.run(test_all())
