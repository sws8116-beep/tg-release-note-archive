import streamlit as st
import pdfplumber
import sqlite3
import pandas as pd
import re
import os

# --- 1. 페이지 설정 ---
st.set_page_config(page_title="보안팀 릴리즈 아카이브 Pro v35.5", layout="wide")

st.markdown("""
    <style>
    .version-header { font-size: 24px; font-weight: 800; color: #0D47A1; background-color: #E3F2FD; padding: 15px; border-radius: 8px; border-left: 8px solid #1565C0; margin-bottom: 15px; }
    .report-box { padding: 20px; border: 1px solid #ddd; background-color: #ffffff; border-radius: 8px; margin-bottom: 25px; }
    .item-box { padding: 10px 14px; margin-bottom: 8px; border-left: 4px solid #90CAF9; background-color: #F5F5F5; font-size: 15px; line-height: 1.6; }
    .highlight { background-color: #FFF59D; color: black; font-weight: bold; padding: 2px 4px; border-radius: 4px; }
    .meta-label { color: #1565C0; font-weight: bold; font-size: 16px; border-bottom: 2px solid #BBDEFB; margin-bottom: 10px; display: inline-block; }
    </style>
    """, unsafe_allow_html=True)

# --- 2. DB 연결 ---
DB_FILE = 'security_notes_archive.db'
conn = sqlite3.connect(DB_FILE, check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT, openssl TEXT, openssh TEXT, improvements TEXT, issues TEXT, raw_text TEXT)''')
conn.commit()

# --- 3. [통합 엔진] 다중 전략 파싱 (Robust Parsing) ---
def parse_pdf_v35(file):
    with pdfplumber.open(file) as pdf:
        full_raw = ""
        extracted_data = [] # 순서 유지용 리스트
        
        for page in pdf.pages:
            p_text = page.extract_text() or ""
            full_raw += p_text + "\n"
            
            # ---------------------------------------------------------
            # [전략 1 & 2] 표(Table) 추출 시도 (기본 + 텍스트 기반)
            # ---------------------------------------------------------
            # 설정 A: 기본 (선 기반)
            # 설정 B: 텍스트 기반 (선 없는 표 대응) -> vertical_strategy: "text"
            strategies = [
                {}, 
                {"vertical_strategy": "text", "horizontal_strategy": "text", "snap_tolerance": 5}
            ]
            
            tables_found = False
            for settings in strategies:
                tables = page.extract_tables(table_settings=settings)
                if tables:
                    tables_found = True
                    last_type = ""
                    last_cat = ""
                    
                    for table in tables:
                        for row in table:
                            # 데이터 정제
                            cells = [str(c).strip() if c else "" for c in row]
                            
                            # 헤더나 빈 행 스킵
                            if not cells or len(cells) < 2: continue
                            if cells[0] in ["구분", "Type", "분류"] or cells[1] in ["항목", "기능분류"]: continue

                            # 매핑 (인덱스 안전 접근)
                            v_type = cells[0]
                            v_cat = cells[1] if len(cells) > 1 else ""
                            v_desc_raw = cells[2] if len(cells) > 2 else ""
                            v_id = cells[3] if len(cells) > 3 else ""

                            # Forward Fill (빈 칸 채우기)
                            if v_type: last_type = v_type
                            else: v_type = last_type
                            
                            if v_cat: last_cat = v_cat
                            else: v_cat = last_cat

                            # 키워드 필터 (쓰레기 데이터 제거)
                            target_keywords = ['개선', '신규', '이슈', '수정', 'BUG', 'TASK', 'Feature', '기능']
                            if v_desc_raw and any(k in v_type for k in target_keywords):
                                # 스마트 요약 (제목 제거)
                                lines = v_desc_raw.split('\n')
                                bullet_lines = [re.sub(r'^[•\-o]\s*', '', l.strip()) for l in lines if l.strip().startswith(('•', '-', 'o '))]
                                final_desc = " ".join(bullet_lines) if bullet_lines else v_desc_raw.replace('\n', ' ')
                                
                                # 포맷팅
                                cat_part = f" {v_cat}" if v_cat else ""
                                id_part = f" ({v_id})" if v_id and v_id.lower() not in ["none", "", "-"] else ""
                                line_str = f"[{v_type}]{cat_part} * {final_desc}{id_part}"
                                
                                if line_str not in extracted_data:
                                    extracted_data.append(line_str)
            
            # ---------------------------------------------------------
            # [전략 3] 텍스트 라인 파싱 (표 추출 실패 시 최후의 보루)
            # ---------------------------------------------------------
            # 표에서 데이터를 못 찾았거나, 보완이 필요할 때 실행
            text_lines = p_text.split('\n')
            for l in text_lines:
                clean_l = l.strip()
                if not clean_l: continue

                # 패턴 1: [신규] ... (대괄호 있음)
                match_bracket = re.match(r'^[•\-]?\s*\[([^\]]+)\]\s*(.*)', clean_l)
                
                # 패턴 2: 신규 ... (대괄호 없이 키워드로 시작)
                # 예: "신규 SSL VPN ..." -> 정규식으로 잡아냄
                match_no_bracket = re.match(r'^(개선|신규|이슈|수정|BUG|TASK)\s+([a-zA-Z0-9_/]+)?\s*(.*)', clean_l)

                formatted = ""
                if match_bracket:
                    tag, body = match_bracket.group(1), match_bracket.group(2)
                    if any(kw in tag for kw in ['개선', '신규', '이슈', '수정']):
                        if '/' in tag:
                            t1, t2 = tag.split('/', 1)
                            formatted = f"[{t1}] {t2} * {body}"
                        else:
                            formatted = f"[{tag}] * {body}"
                
                elif match_no_bracket:
                    # 표가 깨져서 텍스트로만 읽힐 때 유용
                    k_type = match_no_bracket.group(1)
                    k_cat = match_no_bracket.group(2) or ""
                    k_desc = match_no_bracket.group(3)
                    
                    # 너무 짧은 건 제목(Header)일 수 있으니 제외
                    if len(k_desc) > 5: 
                        formatted = f"[{k_type}] {k_cat} * {k_desc}"

                # 중복 방지 후 추가
                if formatted and formatted not in extracted_data:
                    extracted_data.append(formatted)

        # 메타데이터
        v = re.search(r'TrusGuard\s+v?([\d\.]+)', full_raw, re.I)
        version = v.group(1) if v else "Unknown"
        ssl = re.search(r'OpenSSL\s+([\d\.]+[a-z]?)', full_raw, re.I)
        ssh = re.search(r'OpenSSH\s+([\d\.]+p\d+)', full_raw, re.I)

    return {
        "version": version,
        "openssl": ssl.group(1) if ssl else "-",
        "openssh": ssh.group(1) if ssh else "-",
        "content": "\n\n".join(extracted_data),
        "raw": full_raw
    }

# --- 4. 사이드바 ---
if 's_key' not in st.session_state: st.session_state.s_key = "v35"

with st.sidebar:
    st.header("📜 버전 히스토리")
    try:
        hist_df = pd.read_sql_query("SELECT version FROM notes ORDER BY version DESC", conn)
    except:
        hist_df = pd.DataFrame()

    sel_v = st.radio("버전 선택", hist_df['version'].tolist()) if not hist_df.empty else None

    st.divider()
    with st.expander("➕ PDF 등록", expanded=True):
        uploaded = st.file_uploader("파일 선택", accept_multiple_files=True, label_visibility="collapsed")
        if st.button("✅ DB 반영", use_container_width=True):
            if uploaded:
                for f in uploaded:
                    try:
                        info = parse_pdf_v35(f)
                        cursor.execute("SELECT version FROM notes WHERE version = ?", (info['version'],))
                        if not cursor.fetchone():
                            cursor.execute("INSERT INTO notes (version, openssl, openssh, improvements, issues, raw_text) VALUES (?,?,?,?,?,?)",
                                        (info['version'], info['openssl'], info['openssh'], info['content'], "", info['raw']))
                            conn.commit()
                            st.success(f"v{info['version']} 저장됨 ({len(info['content'].splitlines())} 건 추출)")
                        else:
                            st.warning(f"v{info['version']} 이미 존재")
                    except Exception as e:
                        st.error(f"오류: {e}")
                st.rerun()

    with st.expander("🗑️ 데이터 삭제"):
        if not hist_df.empty:
            del_v = st.selectbox("삭제 버전", hist_df['version'].tolist())
            if st.button("🚨 삭제"):
                cursor.execute("DELETE FROM notes WHERE version = ?", (del_v,))
                conn.commit()
                st.rerun()

# --- 5. 메인 렌더링 ---
st.title("🛡️ TrusGuard 통합 관제 (v35.5)")

c1, c2 = st.columns([5,1], vertical_alignment="bottom")
keyword = c1.text_input("검색어 입력", key=st.session_state.s_key)
if c2.button("🔄 초기화"):
    st.session_state.s_key = os.urandom(4).hex()
    st.rerun()

def render_report_card(version, openssl, openssh, content, search_kws=None):
    st.markdown(f"<div class='version-header'>📦 TrusGuard {version}</div>", unsafe_allow_html=True)
    with st.container():
        st.markdown("<div class='report-box'>", unsafe_allow_html=True)
        st.markdown(f"<div class='meta-label'>🔒 보안 컴포넌트</div>", unsafe_allow_html=True)
        st.text(f"OpenSSL: {openssl} / OpenSSH: {openssh}")
        st.markdown("<br>", unsafe_allow_html=True)

        st.markdown(f"<div class='meta-label'>📋 상세 변경 내역</div>", unsafe_allow_html=True)
        if content:
            paras = content.split('\n\n')
            has_content = False
            for p in paras:
                if not p.strip(): continue
                display_text = p.strip()
                if search_kws:
                    if not all(k.lower() in display_text.lower() for k in search_kws): continue
                    for k in search_kws:
                        display_text = re.sub(f"({re.escape(k)})", r"<span class='highlight'>\1</span>", display_text, flags=re.I)
                st.markdown(f"<div class='item-box'>{display_text}</div>", unsafe_allow_html=True)
                has_content = True
            
            if not has_content and search_kws:
                st.info("검색 결과가 없습니다.")
        else:
            st.warning("데이터 추출 실패: PDF 형식이 이미지거나 표 인식이 불가능합니다.")
        st.markdown("</div>", unsafe_allow_html=True)

if keyword:
    kws = keyword.split()
    query = "SELECT * FROM notes WHERE " + " AND ".join(["raw_text LIKE ?" for _ in kws]) + " ORDER BY version DESC"
    res = pd.read_sql_query(query, conn, params=[f'%{k}%' for k in kws])
    if res.empty: st.info("검색 결과 없음")
    else:
        for _, row in res.iterrows(): render_report_card(row['version'], row['openssl'], row['openssh'], row['improvements'], kws)
elif sel_v:
    r = pd.read_sql_query("SELECT * FROM notes WHERE version = ?", conn, params=[sel_v]).iloc[0]
    render_report_card(r['version'], r['openssl'], r['openssh'], r['improvements'])
else:
    st.info("좌측 사이드바에서 PDF 파일을 등록하거나 버전을 선택해주세요.")
